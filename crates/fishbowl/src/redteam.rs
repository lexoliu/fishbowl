//! The gate a red team session is opened through.
//!
//! A `--redteam` session is for targets the operator is authorized to engage: the
//! agent is briefed for offensive work, and egress is forced through an anonymizing
//! transport — Tor first, WARP when Tor cannot be raised, never the machine's own
//! address. That posture's first act on every opening is to ask for the
//! authorization in the terminal. A refusal, a cancelled prompt and a missing
//! terminal all fail the same way: nothing is started.

use std::{fmt::Write as _, io::Write as _};

use anyhow::{Context as _, Result, bail};
use inquire::{
    Confirm, InquireError,
    ui::{Attributes, Color, RenderConfig, StyleSheet, Styled},
};

/// The skull the attestation is asked under.
const SKULL: &str = include_str!("../templates/redteam.txt");

/// The question the confirmation asks, after the frame has been drawn.
const QUESTION: &str =
    "You attest that you hold authorization to engage the targets this session will touch";

/// Bright red, bold — the frame's one color.
const RED: &str = "\u{1b}[1;91m";
/// Ends the frame's color.
const RESET: &str = "\u{1b}[0m";

/// Asks the operator to attest their authorization for this session's targets.
///
/// The default answer is no: an attestation that can be given by accident is not one.
///
/// # Errors
/// Fails when the answer is no, when the prompt is cancelled, or when there is no
/// terminal to ask in — the three cases share the one outcome: nothing is started.
pub fn attest() -> Result<()> {
    std::io::stderr()
        .lock()
        .write_all(frame().as_bytes())
        .context("drawing the red team warning")?;

    let mut render = RenderConfig::default_colored();
    render.prompt_prefix = Styled::new("☠")
        .with_fg(Color::LightRed)
        .with_attr(Attributes::BOLD);
    render.prompt = StyleSheet::new()
        .with_fg(Color::LightRed)
        .with_attr(Attributes::BOLD);
    render.answer = StyleSheet::new()
        .with_fg(Color::LightRed)
        .with_attr(Attributes::BOLD);

    let answer = Confirm::new(QUESTION)
        .with_default(false)
        .with_help_message("anything but an explicit yes ends this before it starts")
        .with_render_config(render)
        .prompt();

    match answer {
        Ok(true) => Ok(()),
        Ok(false) | Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
            bail!("authorization was not attested; nothing was started")
        }
        Err(InquireError::NotTTY) => bail!(
            "red team mode asks for its attestation in a terminal, and there is none to \
             ask in"
        ),
        Err(error) => Err(anyhow::Error::new(error).context("asking for the red team attestation")),
    }
}

/// The boxed warning, in red, that the question is asked under.
fn frame() -> String {
    const TITLE: &str = "R E D   T E A M   M O D E";
    const BODY: &[&str] = &[
        "The agent in this session is briefed for offensive work, and",
        "its egress is forced through an anonymizing transport — Tor",
        "first, WARP when Tor cannot be raised, never the machine's own",
        "address.",
        "",
        "Proceed only for targets you are authorized to engage.",
    ];

    // `true` centres the row: the skull and the title sit in the middle of the box,
    // the body stays flush left where prose belongs.
    let mut rows: Vec<(String, bool)> = SKULL
        .trim_end()
        .lines()
        .map(|line| (line.to_owned(), true))
        .collect();
    rows.push((String::new(), false));
    rows.push((TITLE.to_owned(), true));
    rows.push((String::new(), false));
    rows.extend(BODY.iter().map(|line| ((*line).to_owned(), false)));

    let width = rows
        .iter()
        .map(|(row, _)| row.chars().count())
        .max()
        .unwrap_or_default();
    let inner = "═".repeat(width + 4);
    let mut frame = String::with_capacity(width * (rows.len() + 2));
    frame.push_str(RED);
    let _ = writeln!(frame, "\n  ╔{inner}╗");
    for (row, centred) in &rows {
        let slack = width - row.chars().count();
        let (left, right) = if *centred {
            (slack.div_ceil(2), slack / 2)
        } else {
            (0, slack)
        };
        let _ = writeln!(
            frame,
            "  ║  {}{}{}  ║",
            " ".repeat(left),
            row,
            " ".repeat(right)
        );
    }
    let _ = writeln!(frame, "  ╚{inner}╝\n{RESET}");
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frame_is_a_red_box_around_a_skull() {
        let frame = frame();
        assert!(frame.starts_with(RED), "the frame is drawn in red");
        assert!(frame.contains("R E D   T E A M   M O D E"));
        assert!(frame.contains("████"), "the skull is in the box: {frame}");
        assert!(
            frame.contains("║") && frame.contains("═"),
            "the frame is drawn as a box: {frame}"
        );
        // Every boxed row is the same width — a border that drifts is not a box.
        for line in frame.lines().filter(|line| line.contains('║')) {
            assert!(line.trim_end().ends_with('║'), "an unclosed row: {line}");
        }
    }

    #[test]
    fn the_question_asks_for_authorization() {
        assert!(QUESTION.contains("authorization"));
    }
}
