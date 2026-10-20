//! Растеризация эмодзи в именах серверов. Кэш общий для фонового прогрева и UI.

use slint::{Image, Rgba8Pixel, SharedPixelBuffer};
use std::collections::HashMap;
use std::sync::OnceLock;
use swash::scale::{Render, ScaleContext, Source, StrikeWith};
use swash::shape::{Direction, ShapeContext};
use swash::text::Script;
use swash::FontRef;

pub struct Run {
    pub text: String,
    pub image: Image,
}

pub fn name_runs(name: &str) -> Vec<Run> {
    if name.is_empty() {
        return Vec::new();
    }
    if !name.chars().any(|ch| is_regional(ch) || is_pictograph(ch)) {
        return vec![Run { text: name.to_string(), image: Image::default() }];
    }
    let mut runs = Vec::new();
    let mut text = String::new();
    let chars: Vec<(usize, char)> = name.char_indices().collect();
    let mut index = 0;
    while index < chars.len() {
        let (start, ch) = chars[index];
        if let Some(end) = emoji_end(&chars, index) {
            let piece = name.get(start..end).unwrap_or("");
            if let Some(image) = emoji_image(piece) {
                flush_text(&mut runs, &mut text);
                runs.push(Run { text: String::new(), image });
            } else {
                text.push_str(piece);
            }
            index = chars.iter().position(|(byte, _)| *byte >= end).unwrap_or(chars.len());
            let _ = ch;
            continue;
        }
        text.push(ch);
        index += 1;
    }
    flush_text(&mut runs, &mut text);
    if runs.is_empty() && !name.is_empty() {
        runs.push(Run { text: name.to_string(), image: Image::default() });
    }
    runs
}

fn emoji_end(chars: &[(usize, char)], index: usize) -> Option<usize> {
    let (_, ch) = chars[index];
    if is_regional(ch) {
        let next = index + 1;
        let end_index = if next < chars.len() && is_regional(chars[next].1) { next } else { index };
        return Some(byte_after(chars, end_index));
    }
    if !is_pictograph(ch) && !is_keycap_base(ch) {
        return None;
    }
    let mut cursor = index;
    while cursor + 1 < chars.len() {
        let next = chars[cursor + 1].1;
        if next == '\u{FE0F}' || next == '\u{FE0E}' || is_skin(next) || next == '\u{20E3}' || ('\u{E0020}'..='\u{E007F}').contains(&next) {
            cursor += 1;
            continue;
        }
        if next == '\u{200D}' && cursor + 2 < chars.len() {
            cursor += 2;
            continue;
        }
        break;
    }
    if is_keycap_base(ch) && !is_pictograph(ch) && !chars[index..=cursor].iter().any(|(_, item)| *item == '\u{20E3}') {
        return None;
    }
    Some(byte_after(chars, cursor))
}

fn byte_after(chars: &[(usize, char)], index: usize) -> usize {
    let (byte, ch) = chars[index];
    byte + ch.len_utf8()
}

fn is_regional(ch: char) -> bool {
    ('\u{1F1E6}'..='\u{1F1FF}').contains(&ch)
}

fn is_skin(ch: char) -> bool {
    ('\u{1F3FB}'..='\u{1F3FF}').contains(&ch)
}

fn is_keycap_base(ch: char) -> bool {
    matches!(ch, '0'..='9' | '#' | '*')
}

fn is_pictograph(ch: char) -> bool {
    matches!(ch, '\u{00A9}' | '\u{00AE}' | '\u{203C}' | '\u{2049}' | '\u{2122}' | '\u{2139}' | '\u{2194}'..='\u{2199}' | '\u{21A9}'..='\u{21AA}' | '\u{231A}'..='\u{231B}' | '\u{2328}' | '\u{23CF}' | '\u{23E9}'..='\u{23F3}' | '\u{23F8}'..='\u{23FA}' | '\u{24C2}' | '\u{25AA}'..='\u{25AB}' | '\u{25B6}' | '\u{25C0}' | '\u{25FB}'..='\u{25FE}' | '\u{2600}'..='\u{27BF}' | '\u{2934}'..='\u{2935}' | '\u{2B05}'..='\u{2B07}' | '\u{2B1B}'..='\u{2B1C}' | '\u{2B50}' | '\u{2B55}' | '\u{3030}' | '\u{303D}' | '\u{3297}' | '\u{3299}' | '\u{1F300}'..='\u{1FAFF}')
}

fn flush_text(runs: &mut Vec<Run>, text: &mut String) {
    if text.is_empty() {
        return;
    }
    let value = if runs.last().is_some_and(|run| run.text.is_empty()) {
        text.trim_start().to_string()
    } else {
        std::mem::take(text)
    };
    text.clear();
    if value.is_empty() {
        return;
    }
    runs.push(Run { text: value, image: Image::default() });
}

#[derive(Clone)]
struct EmojiPixels {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

fn emoji_cache() -> &'static std::sync::Mutex<HashMap<String, EmojiPixels>> {
    static CACHE: OnceLock<std::sync::Mutex<HashMap<String, EmojiPixels>>> = OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn image_from_pixels(pixels: &EmojiPixels) -> Image {
    let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(pixels.width, pixels.height);
    let dest = buffer.make_mut_slice();
    for (pixel, chunk) in dest.iter_mut().zip(pixels.rgba.chunks_exact(4)) {
        *pixel = Rgba8Pixel { r: chunk[0], g: chunk[1], b: chunk[2], a: chunk[3] };
    }
    Image::from_rgba8(buffer)
}

/// Renders emoji clusters ahead of the UI thread. `name_runs` then reuses the shared cache.
pub fn warm(names: &[String]) {
    for name in names {
        let _ = name_runs(name);
    }
}

fn emoji_image(cluster: &str) -> Option<Image> {
    if cluster.is_empty() {
        return None;
    }
    if let Some(pixels) = emoji_cache().lock().ok().and_then(|cache| cache.get(cluster).cloned()) {
        return Some(image_from_pixels(&pixels));
    }
    let pixels = render_emoji(cluster)?;
    let image = image_from_pixels(&pixels);
    if let Ok(mut cache) = emoji_cache().lock() {
        cache.insert(cluster.to_string(), pixels);
    }
    Some(image)
}

fn emoji_font() -> Option<&'static [u8]> {
    static FONT: OnceLock<Vec<u8>> = OnceLock::new();
    let bytes = FONT.get_or_init(|| {
        const CANDIDATES: &[&str] = &[
            "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
            "/usr/share/fonts/noto/NotoColorEmoji.ttf",
            "/System/Library/Fonts/Apple Color Emoji.ttc",
            r"C:\Windows\Fonts\seguiemj.ttf",
        ];
        CANDIDATES.iter().find_map(|path| std::fs::read(path).ok()).unwrap_or_default()
    });
    if bytes.is_empty() { None } else { Some(bytes.as_slice()) }
}

fn render_emoji(cluster: &str) -> Option<EmojiPixels> {
    let font_bytes = emoji_font()?;
    let font = FontRef::from_index(font_bytes, 0)?;
    let mut shapes = ShapeContext::new();
    let mut shaper = shapes.builder(font).script(Script::Latin).direction(Direction::LeftToRight).size(32.).build();
    shaper.add_str(cluster);
    let mut glyphs = Vec::new();
    shaper.shape_with(|cluster| {
        glyphs.extend(cluster.glyphs.iter().copied().filter(|glyph| glyph.id != 0));
    });
    if glyphs.is_empty() {
        return None;
    }
    let mut scale = ScaleContext::new();
    let mut scaler = scale.builder(font).size(32.).build();
    let mut layers = Vec::new();
    let mut cursor = 0i32;
    let mut width = 0i32;
    let mut height = 0i32;
    for glyph in glyphs {
        let Some(image) = Render::new(&[Source::ColorBitmap(StrikeWith::BestFit), Source::Outline]).render(&mut scaler, glyph.id) else {
            continue;
        };
        if image.placement.width == 0 || image.placement.height == 0 {
            continue;
        }
        let x = cursor;
        width = width.max(x + image.placement.width as i32);
        height = height.max(image.placement.height as i32);
        cursor += image.placement.width as i32;
        layers.push((x, image));
    }
    if layers.is_empty() || width <= 0 || height <= 0 {
        return None;
    }
    let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(width as u32, height as u32);
    {
        let pixels = buffer.make_mut_slice();
        for (origin_x, image) in &layers {
            let row_width = image.placement.width as i32;
            let row_height = image.placement.height as i32;
            for row in 0..row_height {
                for col in 0..row_width {
                    let x = origin_x + col;
                    let y = row;
                    if x < 0 || y < 0 || x >= width || y >= height {
                        continue;
                    }
                    let source = ((row * row_width + col) * 4) as usize;
                    let Some(bytes) = image.data.get(source..source + 4) else {
                        continue;
                    };
                    pixels[(y * width + x) as usize] = Rgba8Pixel { r: bytes[0], g: bytes[1], b: bytes[2], a: bytes[3] };
                }
            }
        }
        if pixels.iter().all(|pixel| pixel.a == 0) {
            return None;
        }
        let rgba = pixels.iter().flat_map(|pixel| [pixel.r, pixel.g, pixel.b, pixel.a]).collect();
        Some(EmojiPixels { width: width as u32, height: height as u32, rgba })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_becomes_an_image_and_the_name_stays_text() {
        let runs = name_runs("🇩🇪 Франкфурт");
        assert!(runs.iter().any(|run| run.image.size().width > 0), "flag image");
        let text = runs.iter().map(|run| run.text.as_str()).collect::<String>();
        assert!(text.contains("Франкфурт"));
        assert!(!text.contains("🇩🇪"));
    }

    #[test]
    fn plain_name_is_one_text_run() {
        let runs = name_runs("Amsterdam");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].text, "Amsterdam");
        assert_eq!(runs[0].image.size().width, 0);
    }
}
