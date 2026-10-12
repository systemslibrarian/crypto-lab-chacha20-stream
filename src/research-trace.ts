/** Public RFC 8439 §2.3.2 input, isolated from encryption keys and controls. */
import { chachaBlock, serializeBlock } from './quarterround.ts';
import { toHex } from './cipher.ts';

export function researchTrace(roundCount: number, completed: number) {
  if (![6, 7, 20].includes(roundCount)) throw new Error('Choose 6, 7 or 20 whole rounds.');
  const limit = roundCount * 4;
  if (!Number.isInteger(completed) || completed < 0 || completed > limit) throw new Error('Trace step is outside the selected round limit.');
  const key = Uint8Array.from({ length: 32 }, (_, i) => i);
  const nonce = Uint8Array.of(0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0);
  const block = chachaBlock(key, nonce, 1);
  return {
    limit,
    state: [...(completed === 0 ? block.initialState : block.snapshots[completed - 1]!)],
    active: completed === 0 ? [] : [...block.active[completed - 1]!],
    fullOutput: roundCount === 20 && completed === 80 ? toHex(serializeBlock(block.finalState)) : null,
  };
}

export function mountResearchTrace(host: HTMLElement) {
  host.innerHTML = `<h3>Trace a reduced prefix of the round function</h3>
  <p>Nonstandard research view: this uses the public key, nonce and counter from <a href="https://www.rfc-editor.org/rfc/rfc8439#section-2.3.2" target="_blank" rel="noopener noreferrer">RFC 8439 §2.3.2</a>, separate from the encryption controls. One whole round is four quarter-round operations; column and diagonal rounds alternate.</p>
  <label for="research-round-count">Trace length</label>
  <select id="research-round-count"><option value="6">6 rounds — nonstandard prefix</option><option value="7">7 rounds — nonstandard prefix</option><option value="20" selected>20 rounds — RFC 8439 reference</option></select>
  <div class="btn-row"><button type="button" class="btn" id="research-prev">Previous operation</button><button type="button" class="btn" id="research-next">Next operation</button><button type="button" class="btn" id="research-finish">Show selected endpoint</button><button type="button" class="btn" id="research-reset">Reset trace</button></div>
  <p id="research-step-status" role="status" aria-live="polite"></p>
  <div class="trace-table-shell" role="region" tabindex="0" aria-label="Public-input ChaCha research state"><table id="research-state"><caption>Working state before feed-forward; 32-bit words in hexadecimal</caption><tbody></tbody></table></div>
  <p id="research-feedforward"></p>
  <p>This is a round-function trace, not the bit-puncturing attack, an attack-cost measurement or a reduced-round encryption option. The paper’s 7.5-round result remains a cited result; no fractional-round convention is implemented here. Ciphertext generation and the existing session stepper always use full 20-round ChaCha20.</p>`;
  const count = host.querySelector<HTMLSelectElement>('#research-round-count')!;
  let completed = 0;
  const update = () => {
    const n = Number(count.value); const trace = researchTrace(n, completed);
    const phase = completed === 0 ? 'Initial state' : Math.floor((completed - 1) / 4) % 2 === 0 ? 'Column round' : 'Diagonal round';
    host.querySelector('#research-step-status')!.textContent = `${n === 20 ? 'RFC reference' : 'Nonstandard prefix'}: ${n} rounds; ${completed} of ${trace.limit} quarter-round operations. ${phase}.`;
    host.querySelector('#research-state tbody')!.innerHTML = Array.from({ length: 4 }, (_, row) => `<tr>${trace.state.slice(row * 4, row * 4 + 4).map((word, col) => `<td>${trace.active.includes(row * 4 + col) ? '<strong>' : ''}${word.toString(16).padStart(8, '0')}${trace.active.includes(row * 4 + col) ? '</strong>' : ''}</td>`).join('')}</tr>`).join('');
    host.querySelector('#research-feedforward')!.textContent = trace.fullOutput ? `Full 20-round block after feed-forward, serialized little-endian: ${trace.fullOutput}` : 'Feed-forward is not applied in this displayed working state. No reduced-round keystream is offered for encryption.';
    host.querySelector<HTMLButtonElement>('#research-prev')!.disabled = completed === 0;
    host.querySelector<HTMLButtonElement>('#research-next')!.disabled = completed === trace.limit;
  };
  count.addEventListener('change', () => { completed = 0; update(); });
  for (const [id, change] of [
    ['research-prev', () => completed--], ['research-next', () => completed++],
    ['research-finish', () => { completed = Number(count.value) * 4; }], ['research-reset', () => { completed = 0; }],
  ] as const) host.querySelector('#' + id)!.addEventListener('click', () => { change(); update(); });
  update();
}
