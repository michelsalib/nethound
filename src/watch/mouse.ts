// The mouse in `nethound watch`: the terminal reports clicks and the wheel (SGR mouse mode) among
// the keys; they are taken out of what is typed and turned into a selection or a key press.

import {
	type Effect,
	handleKey,
	move,
	type State,
	selectedRow,
	visible,
	webOf,
} from "./state.ts";
import { footerAt, TABLE_TOP, tableRoom } from "./view.ts";

/** Report clicks and the wheel, as ESC [ < button ; x ; y M (pressed) or m (released). */
export const MOUSE_ON = "\x1b[?1000h\x1b[?1006h";
export const MOUSE_OFF = "\x1b[?1006l\x1b[?1000l";

export interface Mouse {
	/** 0 left, 1 middle, 2 right; 64 wheel up, 65 wheel down; with 4, 8, 16 for shift, alt, ctrl. */
	button: number;
	/** Column and line, from 0. */
	x: number;
	y: number;
	pressed: boolean;
}

const ESC = "\x1b";
const SGR = new RegExp(`${ESC}\\[<(\\d+);(\\d+);(\\d+)([Mm])`, "g");

/** The mouse reports in what the terminal sent, the rest (keys), and a report cut short, kept for
 * the next read. */
export function readMouse(data: string): {
	events: Mouse[];
	rest: string;
	pending: string;
} {
	const events: Mouse[] = [];
	const rest = data.replace(SGR, (_, b, x, y, m) => {
		events.push({
			button: Number(b),
			x: Number(x) - 1,
			y: Number(y) - 1,
			pressed: m === "M",
		});
		return "";
	});
	const partial = rest.match(new RegExp(`${ESC}\\[<[\\d;]*$`));
	return partial
		? { events, rest: rest.slice(0, partial.index), pending: partial[0] }
		: { events, rest, pending: "" };
}

/** Rows the wheel moves the selection by, each notch. */
const WHEEL = 3;

/** A click selects the row under it, opens the URL under it, or presses the key under it; the wheel
 * moves the selection. */
export function handleMouse(
	s: State,
	m: Mouse,
	height: number,
): [State, Effect?] {
	if (!m.pressed) return [s];
	const button = m.button & ~(4 | 8 | 16);
	if (button === 64 || button === 65) {
		if (s.confirm) return [s];
		return [move(s, button === 64 ? -WHEEL : WHEEL)];
	}
	if (button !== 0) return [s];
	if (m.y === height - 1) {
		const press = footerAt(s, m.x)?.press;
		return press ? handleKey(s, press) : [s];
	}
	// a question waits for its answer: clicking elsewhere neither answers nor dismisses it
	if (s.confirm) return [s];
	const room = tableRoom(height);
	// the details' first line, under the rule: the URL, when there is one
	const web = webOf(s, selectedRow(s));
	if (m.y === TABLE_TOP + room + 1 && web && web.kind !== "none")
		return handleKey(s, { ch: "o" });
	const at = m.y - TABLE_TOP;
	if (at < 0 || at >= room) return [s];
	const r = visible(s)[s.top + at];
	return r
		? [{ ...s, selected: r.key, filtering: false, message: undefined }]
		: [s];
}
