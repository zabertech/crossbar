// Does this need introduction? No? Good.
window.jQuery = require('jquery');
window.$ = require('jquery');

// Cookie handling
// https://github.com/js-cookie/js-cookie
window.Cookies = require('js-cookie');

// Flatpickr, for date/time selection
// https://github.com/flatpickr/flatpickr
import flatpickr from "flatpickr";
window.flatpickr = flatpickr;

// Support for jinja2 style templates
// https://mozilla.github.io/nunjucks/
window.nunjucks = require('nunjucks');

// YAML Parser
// https://github.com/nodeca/js-yaml
window.yaml = require('js-yaml');

// Autobahn WAMP support
window.autobahn = require('autobahn-browser');

// Nice date picker
// https://github.com/mikecoj/MCDatepicker
import MCDatepicker from 'mc-datepicker';
window.MCDatepicker = MCDatepicker;

// riot-route: Simple JS router
// https://github.com/riot/route/tree/master/doc
//window.route = require('riot-route');
import { route, router, setBase, initDomListeners  } from '@riotjs/route'
window.route = route;
window.router = router;
window.setBase = setBase;
window.initDomListeners = initDomListeners;

import './css/main.css';

