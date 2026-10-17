//! Enough of APR's apr_snprintf to format gmond metric values exactly as gmond does.
//!
//! gmond renders every value with the `fmt` string carried in its packet
//! (`%.2f`, `%u`, `%hu`, `%s`, ...) through apr_snprintf, not glibc printf.
//! APR's floating-point conversion is the UNIX V7 `cvt` routine, which rounds
//! halves up on digits produced by repeated float multiplication, so e.g.
//! 1116625.625 with "%.2f" is "1116625.63" (glibc says "...62"). XML parity
//! depends on reproducing it byte for byte.

#[derive(Clone, Copy, Debug)]
pub enum Arg<'a> {
    Int(i64),
    UInt(u64),
    Float(f64),
    #[cfg_attr(not(test), allow(dead_code))] // gmond escapes string values instead
    Str(&'a str),
}

#[derive(Default)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    zero: bool,
    alt: bool,
    width: usize,
    prec: Option<usize>,
    len: Len,
    conv: char,
}

#[derive(Default, PartialEq)]
enum Len {
    #[default]
    None,
    H,
    Hh,
}

/// Format one argument. Literal text in `fmt` is copied; the first conversion
/// consumes `arg`, later ones (malformed gmetric formats) render as empty.
pub fn format(fmt: &str, arg: Arg) -> String {
    let mut out = String::new();
    let mut chars = fmt.chars().peekable();
    let mut used = false;
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut s = Spec::default();
        while let Some(&f) = chars.peek() {
            match f {
                '-' => s.left = true,
                '+' => s.plus = true,
                ' ' => s.space = true,
                '0' => s.zero = true,
                '#' => s.alt = true,
                _ => break,
            }
            chars.next();
        }
        while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
            s.width = s.width * 10 + d as usize;
            chars.next();
        }
        if chars.peek() == Some(&'.') {
            chars.next();
            let mut p = 0;
            while let Some(d) = chars.peek().and_then(|c| c.to_digit(10)) {
                p = p * 10 + d as usize;
                chars.next();
            }
            s.prec = Some(p);
        }
        loop {
            match chars.peek() {
                Some('h') => {
                    chars.next();
                    s.len = if s.len == Len::H { Len::Hh } else { Len::H };
                }
                Some('l' | 'L' | 'q' | 'j' | 'z' | 't') => {
                    chars.next();
                }
                _ => break,
            }
        }
        let Some(conv) = chars.next() else {
            out.push('%');
            break;
        };
        s.conv = conv;
        if conv == '%' {
            out.push('%');
            continue;
        }
        if used {
            continue;
        }
        used = true;
        out.push_str(&convert(&s, arg));
    }
    out
}

fn as_i64(a: Arg) -> i64 {
    match a {
        Arg::Int(v) => v,
        Arg::UInt(v) => v as i64,
        Arg::Float(v) => v as i64,
        Arg::Str(s) => s.trim().parse().unwrap_or(0),
    }
}

fn as_u64(a: Arg) -> u64 {
    match a {
        Arg::Int(v) => v as u64,
        Arg::UInt(v) => v,
        Arg::Float(v) => v as u64,
        Arg::Str(s) => s.trim().parse().unwrap_or(0),
    }
}

fn as_f64(a: Arg) -> f64 {
    match a {
        Arg::Int(v) => v as f64,
        Arg::UInt(v) => v as f64,
        Arg::Float(v) => v,
        Arg::Str(s) => s.trim().parse().unwrap_or(0.0),
    }
}

fn convert(s: &Spec, arg: Arg) -> String {
    match s.conv {
        'd' | 'i' => {
            let mut v = as_i64(arg);
            v = match s.len {
                Len::H => v as i16 as i64,
                Len::Hh => v as i8 as i64,
                Len::None => v,
            };
            let sign = if v < 0 {
                "-"
            } else if s.plus {
                "+"
            } else if s.space {
                " "
            } else {
                ""
            };
            pad_number(s, sign, "", int_digits(v.unsigned_abs().to_string(), s.prec))
        }
        'u' | 'x' | 'X' | 'o' => {
            let mut v = as_u64(arg);
            v = match s.len {
                Len::H => v as u16 as u64,
                Len::Hh => v as u8 as u64,
                Len::None => v,
            };
            let digits = match s.conv {
                'x' => format!("{v:x}"),
                'X' => format!("{v:X}"),
                'o' => format!("{v:o}"),
                _ => v.to_string(),
            };
            let mut digits = int_digits(digits, s.prec);
            let prefix = match s.conv {
                'x' if s.alt && v != 0 => "0x",
                'X' if s.alt && v != 0 => "0X",
                _ => "",
            };
            if s.conv == 'o' && s.alt && !digits.starts_with('0') {
                digits.insert(0, '0');
            }
            pad_number(s, "", prefix, digits)
        }
        'f' | 'e' | 'E' => {
            let v = as_f64(arg);
            if v.is_nan() || v.is_infinite() {
                // apr_snprintf prints these bare: no sign, no padding with zeros.
                return pad(s.width, s.left, if v.is_nan() { "nan" } else { "inf" }.to_string());
            }
            let prec = s.prec.unwrap_or(6);
            let (body, neg) = conv_fp(s.conv, v, s.alt, prec);
            let sign = if neg {
                "-"
            } else if s.plus {
                "+"
            } else if s.space {
                " "
            } else {
                ""
            };
            pad_number(s, sign, "", body)
        }
        'g' | 'G' => {
            let v = as_f64(arg);
            let prec = match s.prec {
                None => 6,
                Some(0) => 1,
                Some(p) => p,
            };
            let mut g = apr_gcvt(v, prec, s.alt);
            let sign = if let Some(rest) = g.strip_prefix('-') {
                g = rest.to_string();
                "-"
            } else if s.plus {
                "+"
            } else if s.space {
                " "
            } else {
                ""
            };
            if s.alt && !g.contains('.') {
                g.push('.');
            }
            if s.conv == 'G' {
                g = g.replace('e', "E");
            }
            pad_number(s, sign, "", g)
        }
        's' => {
            let st: String = match arg {
                Arg::Str(t) => t.to_string(),
                Arg::Int(v) => v.to_string(),
                Arg::UInt(v) => v.to_string(),
                Arg::Float(v) => v.to_string(),
            };
            let st: String = match s.prec {
                Some(p) => st.chars().take(p).collect(),
                None => st,
            };
            pad(s.width, s.left, st)
        }
        'c' => pad(s.width, s.left, ((as_u64(arg) as u8) as char).to_string()),
        _ => String::new(),
    }
}

fn int_digits(d: String, prec: Option<usize>) -> String {
    match prec {
        Some(0) if d == "0" => String::new(),
        Some(p) if d.len() < p => format!("{}{d}", "0".repeat(p - d.len())),
        _ => d,
    }
}

fn pad(width: usize, left: bool, s: String) -> String {
    let n = s.chars().count();
    if n >= width {
        s
    } else if left {
        format!("{s}{}", " ".repeat(width - n))
    } else {
        format!("{}{s}", " ".repeat(width - n))
    }
}

fn pad_number(s: &Spec, sign: &str, prefix: &str, body: String) -> String {
    let len = sign.len() + prefix.len() + body.len();
    let int_with_prec = matches!(s.conv, 'd' | 'i' | 'u' | 'x' | 'X' | 'o') && s.prec.is_some();
    if s.zero && !s.left && !int_with_prec && len < s.width {
        format!("{sign}{prefix}{}{body}", "0".repeat(s.width - len))
    } else {
        pad(s.width, s.left, format!("{sign}{prefix}{body}"))
    }
}

const NDIG: usize = 80;

/// C modf: (fractional part, integer part), both with the sign of x.
fn modf(x: f64) -> (f64, f64) {
    (x.fract(), x.trunc())
}

/// APR's apr_cvt (apr_ecvt when `eflag`, apr_fcvt otherwise): returns the
/// digit string, the decimal point position and the sign.
fn apr_cvt(arg: f64, ndigits: usize, eflag: bool) -> (Vec<u8>, i32, bool) {
    let ndigits = ndigits.min(NDIG - 2) as isize;
    let mut buf = [0u8; NDIG + 1];
    let mut r2: isize = 0;
    let sign = arg < 0.0;
    let arg = if sign { -arg } else { arg };
    let (mut arg, mut fi) = modf(arg);
    let mut p: usize = 0;
    if fi != 0.0 {
        let mut p1 = NDIG;
        while p1 > 0 && fi != 0.0 {
            let (fj, rest) = modf(fi / 10.0);
            fi = rest;
            p1 -= 1;
            buf[p1] = (((fj + 0.03) * 10.0) as i32 as u8).wrapping_add(b'0');
            r2 += 1;
        }
        while p1 < NDIG {
            buf[p] = buf[p1];
            p += 1;
            p1 += 1;
        }
    } else if arg > 0.0 {
        loop {
            let fj = arg * 10.0;
            if fj < 1.0 {
                arg = fj;
                r2 -= 1;
            } else {
                break;
            }
        }
    }
    let mut p1: isize = ndigits;
    if !eflag {
        p1 += r2;
    }
    if p1 < 0 {
        return (vec![], -(ndigits as i32), sign);
    }
    let mut p1 = p1 as usize;
    let mut decpt = r2 as i32;
    while p <= p1 && p < NDIG {
        arg *= 10.0;
        let (f, j) = modf(arg);
        arg = f;
        buf[p] = (j as i32 as u8).wrapping_add(b'0');
        p += 1;
    }
    if p1 >= NDIG {
        let end = buf[..NDIG - 1].iter().position(|&c| c == 0).unwrap_or(NDIG - 1);
        return (buf[..end].to_vec(), decpt, sign);
    }
    p = p1;
    buf[p1] = buf[p1].wrapping_add(5);
    while buf[p1] > b'9' {
        buf[p1] = b'0';
        if p1 > 0 {
            p1 -= 1;
            buf[p1] += 1;
        } else {
            buf[p1] = b'1';
            decpt += 1;
            if !eflag {
                if p > 0 {
                    buf[p] = b'0';
                }
                p += 1;
            }
        }
    }
    (buf[..p].to_vec(), decpt, sign)
}

/// APR's conv_fp for 'f', 'e' and 'E'. Returns (text without sign, negative).
fn conv_fp(format: char, num: f64, add_dp: bool, precision: usize) -> (String, bool) {
    let (digits, mut decpt, neg) =
        if format == 'f' { apr_cvt(num, precision, false) } else { apr_cvt(num, precision + 1, true) };
    let mut out = String::new();
    let mut d = digits.iter().map(|&c| c as char);
    if format == 'f' {
        if decpt <= 0 {
            out.push('0');
            if precision > 0 {
                out.push('.');
                while decpt < 0 {
                    out.push('0');
                    decpt += 1;
                }
            } else if add_dp {
                out.push('.');
            }
        } else {
            for _ in 0..decpt {
                if let Some(c) = d.next() {
                    out.push(c);
                }
            }
            if precision > 0 || add_dp {
                out.push('.');
            }
        }
    } else {
        if let Some(c) = d.next() {
            out.push(c);
        }
        if precision > 0 || add_dp {
            out.push('.');
        }
    }
    out.extend(d);
    if format != 'f' {
        out.push(format);
        let e = decpt - 1;
        if e != 0 {
            out.push(if e < 0 { '-' } else { '+' });
            let t = e.unsigned_abs().to_string();
            if t.len() == 1 {
                out.push('0');
            }
            out.push_str(&t);
        } else {
            out.push_str("+00");
        }
    }
    (out, neg)
}

/// APR's apr_gcvt (used for %g).
fn apr_gcvt(number: f64, ndigit: usize, altform: bool) -> String {
    let (p1, mut decpt, sign) = apr_cvt(number, ndigit, true);
    let digit = |i: usize| p1.get(i).copied().unwrap_or(b'0') as char;
    let mut ndigit = ndigit as i32;
    let mut out = String::new();
    if sign {
        out.push('-');
    }
    let mut i = ndigit - 1;
    while i > 0 && digit(i as usize) == '0' {
        ndigit -= 1;
        i -= 1;
    }
    let mut k = 0usize;
    if (decpt >= 0 && decpt - ndigit > 4) || (decpt < 0 && decpt < -3) {
        decpt -= 1;
        out.push(digit(k));
        k += 1;
        out.push('.');
        for _ in 1..ndigit {
            out.push(digit(k));
            k += 1;
        }
        out.push('e');
        if decpt < 0 {
            decpt = -decpt;
            out.push('-');
        } else {
            out.push('+');
        }
        if decpt / 100 > 0 {
            out.push((b'0' + (decpt / 100) as u8) as char);
        }
        if decpt / 10 > 0 {
            out.push((b'0' + ((decpt % 100) / 10) as u8) as char);
        }
        out.push((b'0' + (decpt % 10) as u8) as char);
    } else {
        if decpt <= 0 {
            if digit(0) != '0' {
                out.push('.');
            }
            while decpt < 0 {
                decpt += 1;
                out.push('0');
            }
        }
        for i in 1..=ndigit {
            out.push(digit(k));
            k += 1;
            if i == decpt {
                out.push('.');
            }
        }
        if ndigit < decpt {
            while ndigit < decpt {
                ndigit += 1;
                out.push('0');
            }
            out.push('.');
        }
    }
    if out.ends_with('.') && !altform {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected strings are apr_snprintf output from APR 1.7.6 (tools: a C
    // program linked against libapr-1), including APR's %g and %e quirks.
    #[test]
    fn matches_apr() {
        let cases: &[(&str, Arg, &str)] = &[
            ("%.2f", Arg::Float(0.125), "0.13"),
            ("%.2f", Arg::Float(0.375), "0.38"),
            ("%f", Arg::Float(1937.0315094432372), "1937.031509"),
            ("%.1f", Arg::Float(0.0), "0.0"),
            ("%.5f", Arg::Float(2226.522949f32 as f64), "2226.52295"),
            ("%.2f", Arg::Float(1116625.625f32 as f64), "1116625.63"),
            ("%.0f", Arg::Float(486990.5), "486991"),
            ("%.2f", Arg::Float(516097.625), "516097.63"),
            ("%.0f", Arg::Float(2.5), "3"),
            ("%.0f", Arg::Float(3.5), "4"),
            ("%f", Arg::Float(-0.0), "0.000000"),
            ("%.3f", Arg::Float(338.516), "338.516"),
            ("%.1f", Arg::Float(58.1), "58.1"),
            ("%.4f", Arg::Float(0.00005), "0.0001"),
            ("%f", Arg::Float(99.96847943989864f32 as f64), "99.968483"),
            ("%g", Arg::Float(100000.0), "1.e+5"),
            ("%g", Arg::Float(1000000.0), "1.e+6"),
            ("%g", Arg::Float(0.0001), ".0001"),
            ("%g", Arg::Float(0.00001234), "1.234e-5"),
            ("%.3g", Arg::Float(3.14159), "3.14"),
            ("%e", Arg::Float(12345.678), "1.234568e+04"),
            ("%e", Arg::Float(0.0), "0.000000e-01"),
            ("%u", Arg::UInt(3134), "3134"),
            ("%hu", Arg::UInt(70000), "4464"),
            ("%d", Arg::Int(-5), "-5"),
            ("%5d", Arg::Int(42), "   42"),
            ("%-5d", Arg::Int(42), "42   "),
            ("%05d", Arg::Int(42), "00042"),
            ("%x", Arg::UInt(255), "ff"),
            ("%#x", Arg::UInt(255), "0xff"),
            ("%s", Arg::Str("Linux"), "Linux"),
            ("%.3s", Arg::Str("Linux"), "Lin"),
            ("%+.1f", Arg::Float(2.25), "+2.3"),
            ("%.0f", Arg::Float(0.4), "0"),
            ("%.2f", Arg::Float(0.005), "0.01"),
            ("%.2f", Arg::Float(1e20), "100000000000000000000.00"),
            ("%.1f", Arg::Float(-3.25), "-3.3"),
        ];
        for (f, a, want) in cases {
            assert_eq!(format(f, *a), *want, "format {f:?} {a:?}");
        }
    }
}
