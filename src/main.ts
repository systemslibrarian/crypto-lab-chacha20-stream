import './style.css';
import { initUI } from './ui.ts';

initUI();

import { mountResearchTrace } from './research-trace.ts';
mountResearchTrace(document.getElementById('research-trace')!);
