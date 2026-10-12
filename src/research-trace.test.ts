import { expect, test } from 'vitest';
import { researchTrace } from './research-trace.ts';

// Independent RFC round-function implementation: no visualization helper calls.
function reference(wholeRounds: number): number[] {
 const s = [0x61707865,0x3320646e,0x79622d32,0x6b206574,0x03020100,0x07060504,0x0b0a0908,0x0f0e0d0c,0x13121110,0x17161514,0x1b1a1918,0x1f1e1d1c,1,0x09000000,0x4a000000,0];
 const rot = (x:number,n:number) => ((x << n) | (x >>> (32-n))) >>> 0;
 const qr = (a:number,b:number,c:number,d:number) => {
  s[a]=(s[a]!+s[b]!)>>>0;s[d]=rot(s[d]!^s[a]!,16);
  s[c]=(s[c]!+s[d]!)>>>0;s[b]=rot(s[b]!^s[c]!,12);
  s[a]=(s[a]!+s[b]!)>>>0;s[d]=rot(s[d]!^s[a]!,8);
  s[c]=(s[c]!+s[d]!)>>>0;s[b]=rot(s[b]!^s[c]!,7);
 };
 for(let r=0;r<wholeRounds;r++)for(let i=0;i<4;i++) r%2===0 ? qr(i,i+4,i+8,i+12) : qr(i,4+(i+1)%4,8+(i+2)%4,12+(i+3)%4);
 return s;
}
for (const rounds of [6,7,20]) test(`${rounds}-round endpoint matches an independent RFC operation order`, () => {
 const trace=researchTrace(rounds,rounds*4);
 expect(trace.state).toEqual(reference(rounds));
 expect(trace.fullOutput === null).toBe(rounds!==20);
});
test('trace resets to the RFC initial matrix and cannot step beyond its prefix',()=>{
 expect(researchTrace(6,0).state.slice(0,4)).toEqual([0x61707865,0x3320646e,0x79622d32,0x6b206574]);
 for (const [round,step] of [[6,25],[7,-1],[7,1.5],[7.5,30],[8,32],[20,81]])expect(()=>researchTrace(round!,step!)).toThrow();
});
