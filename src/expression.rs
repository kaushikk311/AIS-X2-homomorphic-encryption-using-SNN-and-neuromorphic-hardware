
use std::collections::HashMap;

const FRACTION_DIGITS: usize = 5;
pub const SCALE: i128 = 10i128.pow(FRACTION_DIGITS as u32);
pub const MAX_INPUT: i128 = 1_000_000_000i128 * SCALE;

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Number(i128),                 // fixed-point integer, SCALE = 100_000
    Variable(String),
    Unary { op: char, rhs: Box<Expr> },
    Binary { op: char, lhs: Box<Expr>, rhs: Box<Expr> },
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Number(i128),
    Ident(String),
    Op(char),
    LParen,
    RParen,
}

fn parse_decimal(s: &str) -> Result<i128, String> {
    let s = s.trim();
    if s.is_empty() { return Err("Empty number".into()); }

    let (negative, body) = if let Some(x) = s.strip_prefix('-') {
        (true, x)
    } else if let Some(x) = s.strip_prefix('+') {
        (false, x)
    } else {
        (false, s)
    };

    let mut parts = body.split('.');
    let whole_s = parts.next().unwrap_or("");
    let frac_s = parts.next().unwrap_or("");
    if parts.next().is_some()
        || (whole_s.is_empty() && frac_s.is_empty())
        || !whole_s.chars().all(|c| c.is_ascii_digit())
        || !frac_s.chars().all(|c| c.is_ascii_digit())
        || frac_s.len() > FRACTION_DIGITS {
        return Err(format!("Invalid decimal '{s}': maximum {FRACTION_DIGITS} decimal places"));
    }

    let whole: i128 = if whole_s.is_empty() { 0 } else {
        whole_s.parse().map_err(|_| "Integer part is too large")?
    };
    let mut fraction = frac_s.to_string();
    while fraction.len() < FRACTION_DIGITS { fraction.push('0'); }
    let fractional: i128 = if fraction.is_empty() { 0 } else {
        fraction.parse().map_err(|_| "Invalid fractional part")?
    };
    let magnitude = whole.checked_mul(SCALE)
        .and_then(|v| v.checked_add(fractional))
        .ok_or("Numeric overflow")?;
    let value = if negative { magnitude.checked_neg().ok_or("Numeric overflow")? } else { magnitude };
    if value.unsigned_abs() > MAX_INPUT as u128 {
        return Err("Each literal must be within ±1,000,000,000".into());
    }
    Ok(value)
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() { i += 1; continue; }
        if c.is_ascii_digit() || c == '.' {
            let start = i;
            let mut dots = 0;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                if chars[i] == '.' { dots += 1; }
                if dots > 1 { return Err("A numeric literal cannot contain two decimal points".into()); }
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            out.push(Token::Number(parse_decimal(&s)?));
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') { i += 1; }
            out.push(Token::Ident(chars[start..i].iter().collect()));
            continue;
        }
        match c {
            '+' | '-' | '*' | '/' | '^' => out.push(Token::Op(c)),
            '(' => out.push(Token::LParen),
            ')' => out.push(Token::RParen),
            _ => return Err(format!("Unexpected character '{c}'")),
        }
        i += 1;
    }
    Ok(out)
}

pub fn parse(input: &str) -> Result<Expr, String> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() { return Err("Expression is empty".into()); }
    let mut p = Parser { tokens, pos: 0 };
    let expr = p.expression(0)?;
    if p.pos != p.tokens.len() { return Err("Unexpected token after expression".into()); }
    Ok(expr)
}

struct Parser { tokens: Vec<Token>, pos: usize }

impl Parser {
    fn peek(&self) -> Option<&Token> { self.tokens.get(self.pos) }
    fn take(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() { self.pos += 1; }
        t
    }

    fn expression(&mut self, min_bp: u8) -> Result<Expr, String> {
        let mut lhs = match self.take() {
            Some(Token::Number(n)) => Expr::Number(n),
            Some(Token::Ident(name)) => Expr::Variable(name),
            Some(Token::Op(op @ ('+' | '-'))) => {
                let rhs = self.expression(5)?;
                Expr::Unary { op, rhs: Box::new(rhs) }
            }
            Some(Token::LParen) => {
                let inside = self.expression(0)?;
                match self.take() {
                    Some(Token::RParen) => inside,
                    _ => return Err("Missing closing ')'".into()),
                }
            }
            Some(other) => return Err(format!("Expected a value, found {other:?}")),
            None => return Err("Unexpected end of expression".into()),
        };

        loop {
            let op = match self.peek() {
                Some(Token::Op(op @ ('+' | '-' | '*' | '/' | '^'))) => *op,
                _ => break,
            };
            let (left_bp, right_bp) = match op {
                '+' | '-' => (1, 2),
                '*' | '/' => (3, 4),
                '^' => (6, 5), // right associative
                _ => unreachable!(),
            };
            if left_bp < min_bp { break; }
            self.take();
            let rhs = self.expression(right_bp)?;
            lhs = Expr::Binary { op, lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }
}

// This evaluator is deliberately a LOCAL parser/test oracle only.
// It is not homomorphic and must never be described as encrypted evaluation.
pub fn evaluate_clear_for_testing(
    expr: &Expr,
    vars: &HashMap<String, i128>,
) -> Result<i128, String> {
    match expr {
        Expr::Number(n) => Ok(*n),
        Expr::Variable(name) => vars.get(name).copied()
            .ok_or_else(|| format!("Variable '{name}' has no assigned value")),
        Expr::Unary { op, rhs } => {
            let v = evaluate_clear_for_testing(rhs, vars)?;
            match op {
                '+' => Ok(v),
                '-' => v.checked_neg().ok_or("Negation overflow".into()),
                _ => Err("Unsupported unary operator".into()),
            }
        }
        Expr::Binary { op, lhs, rhs } => {
            let a = evaluate_clear_for_testing(lhs, vars)?;
            let b = evaluate_clear_for_testing(rhs, vars)?;
            match op {
                '+' => a.checked_add(b).ok_or("Addition overflow".into()),
                '-' => a.checked_sub(b).ok_or("Subtraction overflow".into()),
                '*' => a.checked_mul(b).and_then(|v| v.checked_div(SCALE))
                    .ok_or("Multiplication overflow".into()),
                '/' => {
                    if b == 0 { return Err("Division by zero".into()); }
                    a.checked_mul(SCALE).and_then(|v| v.checked_div(b))
                        .ok_or("Division overflow".into())
                }
                '^' => {
                    if b % SCALE != 0 { return Err("Exponent must be an integer".into()); }
                    let exp = (b / SCALE).try_into().map_err(|_| "Exponent must be non-negative and fit u32")?;
                    let mut acc = SCALE;
                    for _ in 0..exp {
                        acc = acc.checked_mul(a).and_then(|v| v.checked_div(SCALE))
                            .ok_or("Power overflow".to_string())?;
                    }
                    Ok(acc)
                }
                _ => Err("Unknown operator".into()),
            }
        }
    }
}

pub fn format_fixed(v: i128) -> String {
    let mag = v.unsigned_abs();
    let whole = mag / SCALE as u128;
    let frac = mag % SCALE as u128;
    let frac_s = format!("{frac:0FRACTION_DIGITS$}").trim_end_matches('0').to_string();
    let sign = if v < 0 { "-" } else { "" };
    if frac_s.is_empty() { format!("{sign}{whole}") }
    else { format!("{sign}{whole}.{frac_s}") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn run(s: &str) -> String {
        let ast = parse(s).unwrap();
        format_fixed(evaluate_clear_for_testing(&ast, &HashMap::new()).unwrap())
    }

    #[test] fn precedence_and_parentheses() {
        assert_eq!(run("(125.5 + 32.25) * 4 - 18 / 3"), "625");
    }
    #[test] fn negative_and_decimal() {
        assert_eq!(run("-2.5 * 4 + 1.25"), "-8.75");
    }
    #[test] fn power_is_right_associative() {
        assert_eq!(run("2^3^2"), "512");
    }
    #[test] fn variables_parse_and_resolve() {
        let ast = parse("alpha * 2 + beta").unwrap();
        let mut vars = HashMap::new();
        vars.insert("alpha".to_string(), 3 * SCALE);
        vars.insert("beta".to_string(), SCALE / 2);
        assert_eq!(format_fixed(evaluate_clear_for_testing(&ast, &vars).unwrap()), "6.5");
    }
    #[test] fn division_by_zero_rejected() {
        let ast = parse("4 / 0").unwrap();
        assert!(evaluate_clear_for_testing(&ast, &HashMap::new()).is_err());
    }
}
