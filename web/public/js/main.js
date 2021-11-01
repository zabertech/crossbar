"use strict";

// Setup
const env = new nunjucks.Environment(new nunjucks.WebLoader('/views'))
const unsubscribe = initDomListeners()

const WPREFIX = 'com.izaber.wamp';
const MPREFIX = 'meta.user';

var connection;
var session;


// Cribbed from: https://stackoverflow.com/questions/10406930/how-to-construct-a-websocket-uri-relative-to-the-page-uri/20161536#20161536
function url(s) {
    var l = window.location;
    return ((l.protocol === "https:") ? "wss://" : "ws://") 
              + l.hostname 
              + (((l.port != 80) && (l.port != 443)) ? ":" + l.port : "") 
              + s;
}

var loginErrorTitle = null;
var loginErrorMessage = null;
var isTrusted = false;

const PERM_DENY = "0";
const PERM_ALLOW = "1";
const PERM_ELEVATED = "-1";

const PERM_MAPPING = {
        'c': 'call',
        'r': 'register',
        'p': 'publish',
        's': 'subscribe',
      };

const PERM_STR_MAPPING = {
        'call': 'c',
        'register': 'r',
        'publish': 'p',
        'subscribe': 's',
      };


function copyInput(src) {
/*****************************************************
 * When attached to a button, will select and copy the
 * data from the targetted input
 *
 * <input value="foo" id="bar">
 * <button onclick="copyInput(this)" data-copy-target="bar">
 * 
 * The above example will put "foo" into the clipboard
 ****************************************************/
  const copyTargetId = src.dataset.copyTarget;
  const copyTarget = document.getElementById(copyTargetId);
  copyTarget.select();
  document.execCommand('copy');

  const popover = new bootstrap.Popover(src, {
                                      'trigger':  'manual',
                                      'content': 'Copied!',
                                      'placement': 'top',
                                    });
  popover.show();
  setTimeout(()=>{ popover.hide(); }, 2000)

}

function parsePerms( perms ) {
/*****************************************************
 * From permissions strings like "crsp" converts them
 * into an object with keys matching permissions
 * constants
 ****************************************************/
    const matches = perms.matchAll(/([crsp])([+]?)/g);
    let permData = {
            'call': PERM_DENY,
            'register': PERM_DENY,
            'publish': PERM_DENY,
            'subscribe': PERM_DENY
        };
    for ( let match of matches ) {

        // Get the permission keyname itself
        const permKey = PERM_MAPPING[match[1]];

        // Set the permission level
        let permValue = PERM_ALLOW;
        switch ( match[2] ) {
          case '+':
            permValue = PERM_ELEVATED;
            break;
        }

        permData[permKey] = permValue;
    }

    return permData;
}

function dumpPerms( permData ) {
/*****************************************************
 * Converts the permissions record back into a perm
 * string
 ****************************************************/
    let perms = '';
    for ( const permKey in PERM_STR_MAPPING ) {
        const permValue = permData[permKey];
        switch ( permValue ) {
          case PERM_DENY:
              break;

          case PERM_ALLOW:
              perms += PERM_STR_MAPPING[permKey];
              break;
              
          case PERM_ELEVATED:
              perms += PERM_STR_MAPPING[permKey] + "+";
              break;
        }
    }
    return perms;
}

function loginPunt( errorTitle, errorMessage ) {
/*****************************************************
 * Handles the login sequence for the user. If the user is
 * not logged in, will bounce the user to the login page
 ****************************************************/
    loginErrorTitle = errorTitle;
    loginErrorMessage = errorMessage;
    router.push('/login');
}

function connect( login, password ) {
/*****************************************************
 * Handles the login sequence for the user. If the user is
 * not logged in, will bounce the user to the login page
 ****************************************************/

    let opts = {
                  url: url('/ws'),
                  realm: 'izaber',
                  authmethods: ['cookie'],
                };

    if ( login ) {
      opts.authid = login;
      opts.authmethods = ['cookie','ticket'];
      opts.onchallenge = (method, info) => {
        return password
      };

      // As cookie auth will supercede ticket, we want to remove the
      // cookie that would trigger it
      // FIXME: We should actually connect and remove this
      // session correctly (via the wamp.close.logout signal)
      Cookies.remove('cbtid');
    }


    // Connect. We connect anyways, as public by default
    // even without a user/pass
    connection = new autobahn.Connection(opts);

    connection.onopen = sess => {
      session = sess;
      sess.call('com.izaber.wamp.auth.whoami').then(res=>{
            console.log("ROLE!", res);
        switch ( res['role'] ) {
          case 'public':
            return loginPunt();
          case 'trust':
          case 'trusted':
            isTrusted = true;
            break;
          default:
            isTrusted = false;
            return router.push(`/users/${res.authid}`);
        }

        switch ( location.hash ) {
          case '':
          case '#/login':
            return router.push('/main');
          default:
            return router.push(location.hash);
        }
      },
      err=>{
        isTrusted = false;
        loginPunt(
          "Error Connecting",
          `Something went wrong: ${err.args[0]}`
        );
        console.log("ERROR:", err);
      });
    };

    connection.onclose = (reason, details) => {
      switch ( details.reason ) {
        case 'wamp.error.no_auth_method':
          return loginPunt();
        case 'wamp.error.invalid_login':
        case 'com.izaber.wamp.invalid_login':
        case 'com.izaber.wamp.error.permissiondenied':
          return loginPunt('Invalid Login','Unknown login or password');
        case 'wamp.error.not_authorized':
          return loginPunt('Not Authorized',details.reason.args[0]);
        default:
          console.log("Close REASON:", details.reason);
      }
    };

    connection.open();
}

// required to set base first
setBase('#');

/*******************************************************************
 * Template funcs
 ******************************************************************/

function startLoader() {
}

function endLoader() {
}

function render( page, tags, targetSelector ) {
  tags ||= {};
  tags.isTrusted = isTrusted;
  const html = env.render(page, tags);
  const target = document.querySelector(targetSelector || 'body');
  target.innerHTML = html;
  return target;
}

function generalErrorMessage(title, message) {
    console.log("General Error:", title, message);
    console.trace(message)
}

/*******************************************************************
 * Data Classes
 ******************************************************************/

var componentCount = 1;

class DataComponent {
  constructor ( opts ) {
  // --------------------------------------------------
    this.opts = opts;
    this.data = opts.data;
    this.template = opts.template;
    this.target = opts.target;
    this.linked = opts.linked || false;
    this._parent = opts.parent;

    this.dcIndex = opts.dcIndex || componentCount++;

    this.linkedElements = {};
    this.onChangeHandlers = {
              '__generic__': [],
          };
  }

  linkedComponent(opts) {
  // --------------------------------------------------
      opts.dcIndex = this.dcIndex;
      opts.data = this.data;
      opts.parent = this._parent;
      opts.isLinkedComponent = true;
      opts.linked = this;
      let linkedComponent = new this.constructor(opts)

      // Make sure the parent receives notifications
      for ( const type in this.onChangeHandlers ) {
          linkedComponent.onChangeHandlers[type] = [...this.onChangeHandlers[type]];
      }

      return linkedComponent;
  }

  get uuid() {
      return this.get('uuid');
  }

  getTags() {
  // --------------------------------------------------
    return {
      dcIndex: this.dcIndex,
      target: this.target,
      ...this.data
    }
  }

  render() {
  // --------------------------------------------------
    this.targetElement = render(this.template, this.getTags(), this.target)
    this.wireUp();
    return this.targetElement;
  }

  unrender() {
  // --------------------------------------------------
    $(this.targetElement).slideUp();
  }

  wireUp () {
  // --------------------------------------------------
  // Wires up all the form and dynamic elements
  //
      const linked = this.targetElement.querySelectorAll('*[data-link]');
      for ( const linkElement of linked ) {
        this.linkFormField(linkElement);
      }

      const linkedAttribs = this.targetElement.querySelectorAll('*[data-link-attribs]');
      for ( const linkElement of linkedAttribs ) {
        let fn = Function(`"use strict";
            let r = arguments[0];
            return (${linkElement.dataset.linkAttribs});
        `);
        this.addOnChangeHandler('__generic__', (key, value)=>{
          const res = fn(this);
          for ( let k in res ) {
            let v = res[k];
            if ( v ) {
              linkElement.setAttribute(k, v);
            }
            else {
              linkElement.removeAttribute(k);
            }
          }
        });
      }

      const linkedHTML = this.targetElement.querySelectorAll('*[data-link-html]');
      for ( const linkElement of linkedHTML ) {
        let fn = Function(`"use strict";
            let r = arguments[0];
            return (${linkElement.dataset.linkHtml});
        `);
        this.addOnChangeHandler('__generic__', (key, value)=>{
            linkElement.innerHTML = fn(this);
        });
      }

      const linkedCSS = this.targetElement.querySelectorAll('*[data-link-css]');
      for ( const linkElement of linkedCSS ) {
        let fn = Function(`"use strict";
            let r = arguments[0];
            return (${linkElement.dataset.linkCss});
        `);
        this.addOnChangeHandler('__generic__', (key, value)=>{
          const res = fn(this);
          for ( let k in res ) {
            if ( res[k] ) {
              linkElement.classList.add(k);
            }
            else {
              linkElement.classList.remove(k);
            }
          }
        });
      }

      // Do the initial pre-exec
      this.runOnChangeHandlers();
  }

  addOnChangeHandler( key, handler ) {
  // --------------------------------------------------
    if (!( key in this.onChangeHandlers )) {
      this.onChangeHandlers [key] = [];
    }
    this.onChangeHandlers [key].push(handler)
  }

  runOnChangeHandlers( key, value ) {
  // --------------------------------------------------
    for ( const fn of this.onChangeHandlers.__generic__ ) {
      fn(key, value);
    }
    if ( !key || !(key in this.onChangeHandlers) ) {
      return;
    }
    for ( const fn of this.onChangeHandlers[key] ) {
      fn(key, value);
    }
  }

  linkFormField( element, key ) {
  // --------------------------------------------------

    // no key value provided? Use the input.name
    if ( !key ) {
        key = element.name;
    }

    // Register interest in this key
    if ( !(key in this.linkedElements) ) {
        this.linkedElements[key] = [];
    }
    this.linkedElements[key].push(element);

    switch ( element.tagName ) {
        case 'INPUT':
            if ( element.type == 'checkbox' ) {
                element.addEventListener('change',ev =>{
                    this.set(key, ev.currentTarget.checked );
                });
                element.checked = this.get(key);
                break;
            }

            else if ( element.type == 'radio' ) {
                element.addEventListener('change',ev =>{
                    this.set(key, ev.currentTarget.value );
                });
                element.checked = this.get(key) == element.value;
                break;
            }

        case 'SELECT':
            element.addEventListener('change',async ev=>{
                try {
                    await this.set(key, ev.currentTarget.value );
                }
                catch (err) {
                  generalErrorMessage('Failed Saving', err);
                  element.value = this.get(key);
                }
            });
            element.value = this.get(key);
            break;
    };
  }

  get(k) {
    return this.data[k];
  }

  async set(k, v) {
  // --------------------------------------------------
    try {

        // If this doesn't have a UUID, it's a record "under construction"
        if ( !this.uuid )  {
          console.log("Short circuit update of ", k, "to", v);
          this.data[k] = v;
          this.runOnChangeHandlers(k, v);
          return;
        }

        // with a uuid, we'll also need to update the database
        let update = await call('.system.db.update', [
                    [ this.uuid ],
                    {[k]:v}
                  ]);

        if ( update ) {
          this.data[k] = v;
          this.runOnChangeHandlers(k, v);
        }

        return update;
    }
    catch (err) {
        console.log("Throwing ERROR:", err.args[0]);
        throw err.args[0];
    }
  }

  unlink(item) {
    // UUID means this doesn't exist
    if ( !this.uuid )  {
      super.unlink(item);
      return;
    }


    session.call(
      WPREFIX+'.system.db.delete', [[item.uuid]]
    ).then(
      res => {
        super.unlink(item);
      },
      err => {
        generalErrorMessage('API Key deletion failure', err.args[0])
      }
    );
  }

  save() {
  }
}

async function call(uri, args, kwargs) {
// --------------------------------------------------
// Usually best called with await.
//
    const data = await session.call(WPREFIX+uri, args, kwargs);
    return data;
}

/*******************************************************************
 * DataCollection
 ******************************************************************/

class DataCollection {
// --------------------------------------------------
  constructor ( opts ) {
    this.opts = opts;
    this._parent = opts.parent;
    this.list = opts.list;
    this.items = [];
    for ( const data of opts.list ) {
      const dcIndex = componentCount++;
      let opts = {
                'data': data,
                'dcIndex': dcIndex,
                'target': `#list-item-${dcIndex}`,
                'parent': this,
              };
      this.items.push(this.instantiate(opts));
    }
    this.template = opts.template;
    this.target = opts.target;
  }

  instantiate( opts ) {
  // --------------------------------------------------
    throw 'NonImplementedError';
  }

  getTags() {
  // --------------------------------------------------
    return {
      items: this.items,
      parent: this._parent,
    }
  }

  wireUp() {
  // --------------------------------------------------
    const te = this.targetElement

    // Locate the linked item list template node
    const tmple = te.querySelector('*[data-link-list-template]');
    tmple.classList.add('d-none')
    this.templateElement = tmple;

    // What we're going to be appending to
    const listTargetSelector = tmple.dataset.linkListTarget;
    this.appendElement = listTargetSelector ? te.querySelector(listTargetSelector)
                                          : tmple;

    // Are we adding to the front or back?
    this.appendMode = tmple.dataset.linkListAppend || 'before';
  }

  get( dcIndex ) {
  // --------------------------------------------------
    for ( const item of this.items ) {
      if ( item.dcIndex == dcIndex ) {
        return item;
      }
    }
    return;
  }

  create( data ) {
    if ( !data ) {
      data = {};
    }
    const dcIndex = componentCount++;
    let opts = {
              'data': data,
              'dcIndex': dcIndex,
              'target': `#list-item-${dcIndex}`,
              'parent': this,
            };
    let item = this.instantiate(opts);
    this.append(item);
    return item;
  }

  append( item ) {
    this.list.push(item.data);
    this.items.push(item);
    this.renderItem(item);
  }

  unlink( item ) {
  // --------------------------------------------------
  // Attempts to remove the item from the database
  //
    // Find and remove the entry from the list
    const index = this.list.indexOf(item);
    if (index > -1) {
      this.list.splice(index,1);
    }

    // Remove it from display
    item.unrender();
  }

  renderItem( item ) {
  // --------------------------------------------------
  // Create a clone of the target tree
    const itemNode = this.templateElement.cloneNode(true);
    const appendElement = this.appendElement;
    const parentNode = appendElement.parentNode;
    itemNode.id = `list-item-${item.dcIndex}`;
    itemNode.dataset.dcindex = item.dcIndex;
    itemNode.classList.remove('d-none')

    // Insert the new cloned node.
    if ( this.appendMode == 'after' ) {
      parentNode.insertBefore(itemNode, appendElement.nextSibling);
    }
    else {
      parentNode.insertBefore(itemNode, appendElement);
    }

    item.render()
  }

  render() {
  // --------------------------------------------------
    console.log("Collection render:", this.template, this.target);
    this.targetElement = render(this.template, this.getTags(), this.target)
    this.wireUp();

    // Do a quick pass of creating all the required
    // entries
    for ( const item of this.items ) {
      this.renderItem(item);
    }
    return this.targetElement;
  }
}

/*******************************************************************
 * NexusAPIPermissions
 ******************************************************************/

class NexusAPIKeyPermission extends DataComponent {
  constructor (opts) {
    opts.template ||= 'apikey_permission.html'
    super(opts);
  }

  set(k, v) {
    const apikey = this._parent._parent;

    switch (k) {
      case 'call':
      case 'register':
      case 'subscribe':
      case 'publish':
        let permData = parsePerms(this.get('allow'));
        permData[k] = v;
        let perms = dumpPerms(permData);
        k = 'allow';
        v = perms;
      default:
        super.set(k,v);
        apikey.set('permissions', apikey.data.permissions);
    }
  }

  get(k) {
    switch (k) {
      case 'call':
      case 'register':
      case 'subscribe':
      case 'publish':
        let permData = parsePerms(this.get('allow'));
        return permData[k]
      default:
        return super.get(k);
    }
  }

  showModal() {
    // We create a throwaway item
    const apiKey = this._parent._parent;
    const linkedItem = this.linkedComponent({
                                template: 'perm.html',
                                target: `#perm-modal-${apiKey.uuid} .modal-content`,
                            })
    linkedItem.render();
    apiKey.permModal.show();
  }

  render() {
    super.render();

    if ( !this.linked ) {
      this.targetElement.addEventListener('click', event => {
        this.showModal();
      });
    }
  }
}

class NexusAPIKeyPermissions extends DataCollection {
  constructor (opts) {
    opts.template ||= 'apikey_permissions.html'
    opts.target ||= '#api-key-permissions';
    super(opts);
  }

  instantiate( opts ) {
    return new NexusAPIKeyPermission(opts);
  }

  render() {
    const targetElement = super.render();

    // Attach to click for creating new perm records
    const createElem = targetElement.querySelector('.api-key-permission-create');
    createElem.addEventListener('click', event => {
      const item = this.create({
              'perms': '',
              'uri': '',
            });
      item.showModal();
    });
  }
};

/*******************************************************************
 * NexusAPIKeys
 ******************************************************************/

class NexusAPIKey extends DataComponent {
  constructor (opts) {
    opts.template ||= 'apikey.html'
    super(opts);
    this.permissions = new NexusAPIKeyPermissions({
        list: opts.data.permissions,
        target: `#api-key-permissions-${this.uuid}`,
        parent: this,
    })
  }

  get login() {
    return this._parent._parent.login;
  }

  get key() {
    return this.get('key');
  }

  set(k, v) {
  // --------------------------------------------------
    session.call(WPREFIX+'.system.db.update', [
        [ this.uuid ],
        {[k]:v}
    ]).then(
      updated=>{
        if ( updated ) { super.set(k, v); }
      },
      err=>{
        generalErrorMessage('Failed Saving', err.args[0]);
        throw err.args[0];
      }
    );
  }

  /*
  save(success, error) {
    const apikey = this.key;

    session.call(WPREFIX+'.system.apikey.update', [this.login, apikey, this.data]).then(
      updated=>{
        if ( success ) success( this, updated );
      },
      err=>{
        generalErrorMessage('Failed saving api key', err.args[0]);
        if ( error ) error( this, err );
      }
    );
  }
  */

  render() {
    super.render();
    this.permissions.render();

    // This enables a date/time selector for the expiry dates
    flatpickr(`#input-${this.uuid}-expires`, {
      enableTime: true,
    });

    // Activate the Modal dialog for api key (for perms)
    const permModalElement = document.getElementById(`perm-modal-${this.uuid}`);
    this.permModal = new bootstrap.Modal(permModalElement, {});

    // Let's make it possible to delete the record as well
    this.deleteElement = this.targetElement.querySelector('.delete-button');
    this.deleteElement.addEventListener('click', event => {
      this._parent.unlink(this);
    });

  }
}

class NexusAPIKeys extends DataCollection {
  constructor (opts) {
    opts.template ||= 'apikeys.html'
    opts.target ||= '#api-keys';
    super(opts);
  }

  instantiate( opts ) {
    return new NexusAPIKey(opts);
  }


  unlink(item) {
    session.call(
      WPREFIX+'.system.db.delete', [[item.uuid]]
    ).then(
      res => {
        super.unlink(item);
      },
      err => {
        generalErrorMessage('API Key deletion failure', err.args[0])
      }
    );
  }

  render() {
    const targetElement = super.render();

    // For the new API key creation button
    const createElem = targetElement.querySelector('.api-key-create');
    createElem.addEventListener('click', async event => {

      let defaults = {};

      let data = await call('.system.db.create',[
                          this._parent.uuid,
                          'apikeys',
                          defaults
                      ]);

      console.log("apiKeyRec:", data);
      const item = this.create(data);
      console.log("item:", item);

      // open metadata
      const detailsElement = item.targetElement.querySelector('.api-key-details');
      const collapser = new bootstrap.Collapse(detailsElement);
      collapser.show();
    });
  }
};



/*******************************************************************
 * NexusMetadata
 ******************************************************************/

class NexusMetadatum extends DataComponent {
  constructor (opts) {
    opts.template ||= 'metadatum.html'
    super(opts);
  }

  get key() {
    return this.get('key');
  }

  get value() {
    return this.get('value')
  }

  showModal() {
    const metadata = this._parent;
    metadata.modal.show();
  }

  render() {
    let targetElement = super.render();
    const editor = this.editor = ace.edit(`value-${this.uuid}`);
    editor.setTheme("ace/theme/clouds");
    editor.session.setMode("ace/mode/yaml");
    editor.on('blur', ()=> {
      const val = editor.getSession().getValue();
      // validate the data
      this.set('value_yaml', val);
    });

    /*
     * FIXME/TODO: Perhaps we should have ongoing 
     * YAML validation tests happening
    const that = this;
    editor.getSession().on('change', () => {
      if ( that.editorTimeout ) {
        clearTimeout(that.editorTimeout);
      }
      that.editorTimeout = setTimeout(()=>{
        const val = editor.getSession().getValue();
        clearTimeout(that.editorTimeout);
      }, 500);
    });
    */

    editor.setValue(this.value);
    editor.clearSelection();

    // Let's make it possible to delete the record as well
    this.deleteElement = this.targetElement.querySelector('.delete-button');
    this.deleteElement.addEventListener('click', event => {
      this._parent.unlink(this);
    });
  }
}

class NexusMetadata extends DataCollection {

  instantiate( opts ) {
    return new NexusMetadatum(opts);
  }

  constructor (opts) {
    opts.template ||= 'metadata.html'
    opts.target ||= '#metadata';
    super(opts);
  }

  unlink(item) {
    session.call(
      WPREFIX+'.system.db.delete', [[item.uuid]]
    ).then(
      res => {
        super.unlink(item);
      },
      err => {
        generalErrorMessage('Metadata deletion failure', err.args[0])
      }
    );
  }

  render() {
    const targetElement = super.render();

    // Attach to click for creating new perm records
    const createElem = targetElement.querySelector('.metadatum-create');
    createElem.addEventListener('click', async event => {
      // As the system is unhappy with blank uris, we will craft
      // one randomly
      let d = new Date();
      let key = WPREFIX + "." + d.getTime();
      let defaults = { key, value: 'null' };

      let data = await call('.system.db.create',[
                          this._parent.uuid,
                          'metadata',
                          defaults 
                      ]);

      const item = this.create(data);

      // open metadata
      const detailsElement = item.targetElement.querySelector('.metadatum-details');
      const collapser = new bootstrap.Collapse(detailsElement);
      collapser.show();

    });
  }
};

/*******************************************************************
 * NexusUser
 ******************************************************************/

class NexusUser extends DataComponent {
  constructor (opts) {
    opts.template ||= 'user.html'
    opts.target ||= 'body';
    super(opts);
    opts.data.plaintext_password ||= ''

    if ( opts.data.apikeys ) {
        this.apiKeys = new NexusAPIKeys({
                              list: opts.data.apikeys,
                              parent: this,
                          });
    }
    if ( opts.data.metadata ) {
        this.metadata = new NexusMetadata({
                              list: opts.data.metadata,
                              target: `#metadata`,
                              parent: this,
                          });
    }
  }

  get login() {
  // --------------------------------------------------
    return this.data.login;
  }

  render() {
    let targetElement = super.render();

    if ( this.apiKeys ) {
        this.apiKeys.render();
    }
    if ( this.metadata ) {
        this.metadata.render();
    }
    return targetElement;
  }
};


class NexusUserCreate extends DataComponent{

  async login_exists( login ) {
      // Returns true if login already exists
      let res = await call('.system.db.query',
                      ['users', [['login','=',login]]]);
      console.log("GOT RESULT", res);
      return res.hits > 0
  }

  fieldSetError(field, message) {
      for ( let e of this.linkedElements[field] ) {
          let err = e.parentElement.querySelector('.invalid-feedback');
          err.innerHTML = message;
          e.setCustomValidity(message);
          e.classList.add('is-invalid');
      }
  }
  fieldClearError(field) {
      for ( let e of this.linkedElements[field] ) {
          let err = e.parentElement.querySelector('.invalid-feedback');
          err.innerHTML = '';
          e.setCustomValidity('');
          e.classList.add('is-valid');
      }
  }

  async set(k, v) {
      if ( k == 'login' ) {
          if ( await this.login_exists(v) ) {
              this.fieldSetError(k, 'Someone is already using this login!');
          }
          else {
              this.fieldClearError(k);
              if (!this.get('upn')) {
                  let newUPN = `${v}@nexus`
                  await this.set('upn', newUPN);
                  for ( let e of this.linkedElements['upn'] ) {
                    e.value = newUPN;
                  }
              }
          }
      }
      return await super.set(k,v);
  }
}

/*******************************************************************
 * NexusURI
 ******************************************************************/

class NexusRolePermission extends DataComponent {
  constructor (opts) {
    opts.template ||= 'role_permission.html'
    opts.target ||= 'body';
    super(opts);
  }

  render() {
    super.render();

    if ( !this.linked ) {
      this.targetElement.addEventListener('click', event => {
        this.showModal();
      });
    }
  }


  showModal() {
    // We create a throwaway item
    const role = this._parent._parent;
    const linkedItem = this.linkedComponent({
                                template: 'role_permission_new.html',
                                target: `#role-modal .modal-content`,
                            })
    linkedItem.render();
    role.permModal.show();

    // Now attach some events to the "create" button
    let saveButton = linkedItem.targetElement.querySelector('.btn-primary');
    let form = linkedItem.targetElement.querySelector('form');
    saveButton.addEventListener(
          'click', async ev=> {

              // do nothing if we're not allowed anything yet
              if ( !form.checkValidity() ) {
                  form.classList.add('was-validated');
                  return;
              }

              // Save the new record
              await session.call(WPREFIX+'.system.db.update', [
                [ role.uuid ],
                { permissions: role.data.permissions }
              ]);

              role.permModal.hide();
          }
      );


  }

  async set(k, v) {
    const apikey = this._parent._parent;

    try {
      switch (k) {
        case 'call':
        case 'register':
        case 'subscribe':
        case 'publish':
          let permData = parsePerms(this.get('perms'));
          permData[k] = v;
          let perms = dumpPerms(permData);
          k = 'perms';
          v = perms;
        default:
          await super.set(k,v);
      }
    }
    catch(err) { 
      throw err;
    }
  }

  get(k) {
    switch (k) {
      case 'call':
      case 'register':
      case 'subscribe':
      case 'publish':
        let permData = parsePerms(this.get('perms'));
        return permData[k]
      default:
        return super.get(k);
    }
  }

};

class NexusRolePermissions extends DataCollection {
  constructor (opts) {
    opts.template ||= 'role_permissions.html'
    opts.target ||= '#role-permissions';
    super(opts);
  }

  instantiate( opts ) {
    return new NexusRolePermission(opts);
  }

  render() {
    const targetElement = super.render();

    // Attach to click for creating new perm records
    const createElem = targetElement.querySelector('.role-permission-create');
    createElem.addEventListener('click', event => {
      const item = this.create({
              'perms': '',
              'uri': '',
            });
      item.showModal();
    });
  }
};


/*******************************************************************
 * NexusRole
 ******************************************************************/

class NexusRole extends DataComponent {
  constructor (opts) {
    opts.template ||= 'role.html'
    opts.target ||= 'body';
    super(opts);

    this.permissions = new NexusRolePermissions({
        list: opts.data.permissions,
        target: `#role-permissions-${this.uuid}`,
        parent: this,
    })
  }

  set(k, v) {
  // --------------------------------------------------
    console.log("TRYING TO SAVE:", this.uuid);
    session.call(WPREFIX+'.system.db.update', [
        [ this.uuid ],
        {[k]:v}
    ]).then(
      updated=>{
        if ( updated ) { super.set(k, v); }
      },
      err=>{
        generalErrorMessage('Failed Saving', err.args[0]);
        throw err.args[0];
      }
    );
  }

  render() {
    super.render();
    this.permissions.render();

    // Activate the Modal dialog for api key (for perms)
    const permModalElement = document.getElementById(`role-modal`);
    this.permModal = new bootstrap.Modal(permModalElement, {});

    // Let's make it possible to delete the record as well
    /*
    this.deleteElement = this.targetElement.querySelector('.delete-button');
    this.deleteElement.addEventListener('click', event => {
      this._parent.unlink(this);
    });
    */
  }
};


/*******************************************************************
 * NexusURI
 ******************************************************************/

class NexusURI extends DataComponent {
  constructor (opts) {
    opts.template ||= 'uri.html'
    opts.target ||= 'body';
    super(opts);
  }


  get description() {
    return this.get('description')
  }

  set(k, v) {
  // --------------------------------------------------
    console.log("TRYING TO SAVE:", this.uuid);
    session.call(WPREFIX+'.system.db.update', [
        [ this.uuid ],
        {[k]:v}
    ]).then(
      updated=>{
        if ( updated ) { super.set(k, v); }
      },
      err=>{
        generalErrorMessage('Failed Saving', err.args[0]);
        throw err.args[0];
      }
    );
  }


  render() {
    let targetElement = super.render();
    const editor = this.editor = ace.edit(`description-${this.uuid}`);
    editor.setTheme("ace/theme/clouds");
    editor.session.setMode("ace/mode/yaml");
    editor.on('blur', ()=> {
      const val = editor.getSession().getValue();
      // validate the data
      this.set('description', val);
    });

    editor.setValue(this.description);
    editor.clearSelection();
  }
};


/*******************************************************************
 * Login Page
 ******************************************************************/
// create a route stream
const loginStream = route('/login')
loginStream.on.value(() => {

  // Get the template
  const loginHTML = render('login.html');

  // Then let's add the error messages if there are any
  if ( loginErrorTitle ) {
      let errElem = document.getElementById('system-error');
      let headerElem = errElem.querySelector('.alert-heading');
      headerElem.innerHTML = loginErrorTitle;
      let contentElem = errElem.querySelector('p');
      contentElem.innerHTML = loginErrorMessage;
      errElem.classList.remove('d-none')

      // Clear the flag
      loginErrorTitle =  null;
      loginErrorMessage =  null;
  }

  const loginForm = document.getElementById('login-form');
  loginForm.onsubmit = () => {
  // --------------------------------------------------
      const loginInput = document.getElementById('login-form-login');
      const passwordInput = document.getElementById('login-form-password');
      const loginValue = loginInput.value;
      const passwordValue = passwordInput.value;
      try {
          connect(loginValue, passwordValue);
          return false;
      }
      catch (err) {
          loginPunt("Internal Error", `Details: ${err}. Please contact IT`);
      }
  };
})

/*******************************************************************
 * Logout Page
 ******************************************************************/

const logoutStream = route('/logout')
logoutStream.on.value(() => {
  if ( connection ) {
    connection.close('wamp.close.logout','Bibi!')
  }
  router.push('/login');
});

/*******************************************************************
 * Roles List
 ******************************************************************/
const rolesStream = route('/roles')
rolesStream.on.value(() => {
  startLoader();
  session.call('com.izaber.wamp.system.db.query',['roles', []]).then(
    res=>{
      endLoader();
      render('roles.html',res);
    },
    err=>{
      console.log("Unable to get roles!", err)
      endLoader();
    },
  );
});


/*******************************************************************
 * Users list
 ******************************************************************/

async function updateUsersForm(q) {
// This will be invoked whenver a new dataset is required from the 
// db search
//
// Arguments:
//    - q: string query
//    - page: int page
//    - enabled: bool
//    - limit: int max size of page
// 
  startLoader();

  let conditions = []
  if ( q.has('q') ) {
    let query = q.get('q')
    conditions.push([
      'OR', [
        ['login', 'ilike', query],
        ['name', 'ilike', query],
        ['role', 'ilike', query],
      ]])
  }

  if ( q.get('enabled') || !q.has('enabled')) {
    conditions.push([ 'enabled', '=', true ])
    q.set('enabled', true);
  }
  let page_index = parseInt(q.get('page') || 0)
  let limit = parseInt(q.get('limit') || 20)

  // qs = query string
  let qs = (k, v) => {
                      let nq = new URLSearchParams(q.toString());
                      nq.set(k, v);
                      return nq.toString();
                  };

  // s = sort
  let sort = ['login','asc'];
  if ( q.get('s') ) {
    let ks = q.get('s').split(':')
    sort = [ks[0], ks[1]]
  }

  try {
    let result = await call('.system.db.query',
                                  ['users',conditions],
                                  {
                                    'sort':[sort],
                                    'limit':limit,
                                    'page_index': page_index,
                                  }
                                );
    result.qs = qs;
    result.sortKey = sort[0];
    result.sortOrder = sort[1];
    let targetElement = render('users.html', result);

    // Attach events to the form elements for searching
    let filterEnabled = targetElement.querySelector('#filter-enabled');
    if ( q.get('enabled') ) {
      filterEnabled.checked = true;
    }
    filterEnabled.addEventListener(
        'change', ev => {
            q.set('enabled', ev.currentTarget.checked ? '1' : '');
            updateUsersForm(q);
        }
    );

    // Attach events to the search input
    let filterQuery = targetElement.querySelector('#filter-query');
    filterQuery.addEventListener(
        'change', ev => {
            q.set('q', ev.currentTarget.value );
            updateUsersForm(q);
        }
    );
    filterQuery.focus();
    if ( q.get('q') ) {
        filterQuery.value = q.get('q');
    }

    // Setup for new user creation UI
    let newUserClickable = targetElement.querySelector('.user-create');
    newUserClickable.addEventListener(
        'click', async ev=>{
            let newUserModalElement = targetElement.querySelector('#new-user-modal');
            let newUserModal = new bootstrap.Modal(newUserModalElement, {});

            let data = {
                            'login': '',
                            'name': '',
                            'enabled': true,
                            'upn': '',
                            'plaintext_password': '',
                            'source': 'local',
                            'role': 'frontend',
                        };
            let user = new NexusUserCreate({
                          template: 'user_new.html',
                          target: '.modal-content',
                          data: data,
                        });

            // let modalContents = render('user_new.html', {}, '.modal-content')
            newUserModal.show();
            user.render();

            // Now attach some events to the "create" button
            let saveButton = user.targetElement.querySelector('.btn-primary');
            let form = user.targetElement.querySelector('form');
            saveButton.addEventListener(
                  'click', async ev=> {

                      // do nothing if we're not allowed anything yet
                      if ( !form.checkValidity() ) {
                          form.classList.add('was-validated');
                          return;
                      }

                      // Great, let's add the user to the database
                      let newUser = await call('.system.db.create',[
                                            '%root',
                                            'users',
                                            user.data
                                        ])

                      // And bounce to the new user page
                      router.push(`/users/${user.data.login}`)
                  }
              );

        }
    );
  }
  catch (err) {
    console.log("User query raise exception:", err);
  }

  endLoader();
}

const usersStream = route('/users(.*)')
usersStream.on.value( async (ev) => {
  await updateUsersForm(ev.searchParams);
});

/*******************************************************************
 * User Edit
 ******************************************************************/
const userDetailedStream = route('/users/:login')
var userComponent = null;
userDetailedStream.on.value(url=> {
  startLoader();


  const login = unescape(url.params.login);
  session.call(
          'com.izaber.wamp.system.db.query',
          [
              'users',
              [['login','=',login]]
          ],
          {'yaml':true}
      ).then(
          res=>{
            if ( res['hits'] == 0 ) {
                throw 'MissingResult';
            }
            let user = res['records'][0];
            userComponent = new NexusUser({ data: user });
            userComponent.render();
            endLoader()
          },
          err=>{
            console.log("Unable to get users!", err)
            endLoader();
          },
  );
})


/*******************************************************************
 * Role Edit
 ******************************************************************/
const roleDetailedStream = route('/roles/:role')
var roleComponent = null;
roleDetailedStream.on.value(async url=> {
  startLoader();

  // Fetch the role data if available
  const role = url.params.role;
  let roleResult = await call('.system.db.query', ['roles',[['role','=',role]]]);
  if ( roleResult.hits == 0 ) {
      throw 'MissingResult';
  }
  let roleRec = roleResult.records[0];

  roleComponent = new NexusRole({ data: roleRec });
  roleComponent.render();
  endLoader()
})

/*******************************************************************
 * URIs List
 ******************************************************************/
async function updateURIsList(q) {
// This will be invoked whenver a new dataset is required from the 
// db search
//
// Arguments:
//    - q: string query
//    - page: int page
//    - enabled: bool
//    - limit: int max size of page
// 
  startLoader();

  let conditions = []
  if ( q.has('q') ) {
    let query = q.get('q')
    conditions.push([
      'OR', [
        ['uri', 'ilike', query],
        ['peer', 'ilike', query],
        ['authid', 'ilike', query],
        ['description', 'ilike', query],
      ]])
  }

  if ( q.has('system') && q.get('system') ) {
    q.set('system', 1);
  }
  else {
    conditions.push([ 'system', '=', false ])
  }

  let page_index = parseInt(q.get('page') || 0)
  let limit = parseInt(q.get('limit') || 20)

  // qs = query string
  let qs = (k, v) => {
                      let nq = new URLSearchParams(q.toString());
                      nq.set(k, v);
                      return nq.toString();
                  };

  // s = sort
  let sort = ['uri','asc'];
  if ( q.get('s') ) {
    let ks = q.get('s').split(':')
    sort = [ks[0], ks[1]]
  }

  try {
    let result = await call('.system.db.query',
                              ['uris', conditions],
                              {
                                'sort': [sort],
                                'limit': limit,
                                'page_index': page_index,
                              }
                            );
    result.qs = qs;
    result.sortKey = sort[0];
    result.sortOrder = sort[1];
    let targetElement = render('uris.html', result);

    // Attach events to the form elements for searching
    let filterSystem = targetElement.querySelector('#filter-system');
    if ( q.get('system') ) {
      filterSystem.checked = true;
    }
    filterSystem.addEventListener(
        'change', ev => {
            q.set('system', ev.currentTarget.checked ? '1' : '');
            updateURIsList(q);
        }
    );

    // Attach events to the search input
    let filterQuery = targetElement.querySelector('#filter-query');
    filterQuery.addEventListener(
        'change', ev => {
            q.set('q', ev.currentTarget.value );
            updateURIsList(q);
        }
    );
    filterQuery.focus();
    if ( q.get('q') ) {
        filterQuery.value = q.get('q');
    }

  }
  catch (err) {
    console.log("URIs query raise exception:", err);
  }

  endLoader();
}


const urisStream = route('/uris(.*)')
urisStream.on.value(async (ev) => {
  await updateURIsList(ev.searchParams);
});


/*******************************************************************
 * URI Edit
 ******************************************************************/
const uriDetailedStream = route('/uris/:key')
var uriComponent = null;
uriDetailedStream.on.value(url=> {
  startLoader();

  const key = url.params.key;
  session.call(
          'com.izaber.wamp.system.db.query',
          [
              'uris',
              [['key','=',key]]
          ],
          {'yaml':true}
      ).then(
          res=>{
            if ( res['hits'] == 0 ) {
                throw 'MissingResult';
            }
            let uri = res['records'][0];
            uriComponent = new NexusURI({ data: uri });
            uriComponent.render();
            endLoader()
          },
          err=>{
            console.log("Unable to get uris!", err)
            endLoader();
          },
  );
})



/*******************************************************************
 * Main Page
 ******************************************************************/
const mainStream = route('/main')
mainStream.on.value(() => {
  render('main.html', {}, 'body');
});


// triggered on each route event
router.on.value(path => {
  const hashIndex = path.indexOf('#');
  if ( hashIndex < 0 ) {
    return;
  }

  let truePath = path.substr(hashIndex+1)
  router.push(truePath);
})

connect();

