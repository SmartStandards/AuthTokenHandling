(function () {
  'use strict';

  // ======================================================================
  //  host bridge ({id, cmd, args} -> {id, ok, result, error})
  // ======================================================================

  let nextRequestId = 1;
  const pendingRequests = new Map();

  function callHost(command, args) {
    return new Promise((resolve, reject) => {
      const id = nextRequestId++;
      pendingRequests.set(id, { resolve: resolve, reject: reject });
      window.chrome.webview.postMessage({ id: id, cmd: command, args: args || {} });
    });
  }

  window.chrome.webview.addEventListener('message', (event) => {
    const reply = event.data;
    const pending = pendingRequests.get(reply.id);
    if (!pending) {
      return;
    }
    pendingRequests.delete(reply.id);
    if (reply.ok) {
      pending.resolve(reply.result);
    } else {
      pending.reject(new Error(reply.error));
    }
  });

  // ======================================================================
  //  helpers
  // ======================================================================

  function $(id) {
    return document.getElementById(id);
  }

  function el(tag, className, text) {
    const element = document.createElement(tag);
    if (className) {
      element.className = className;
    }
    if (text !== undefined && text !== null) {
      element.textContent = text;
    }
    return element;
  }

  function clone(value) {
    return JSON.parse(JSON.stringify(value));
  }

  let toastTimer = null;
  function toast(message, isError) {
    const box = $('toast');
    box.textContent = message;
    box.className = isError ? 'toast error' : 'toast';
    if (toastTimer) {
      clearTimeout(toastTimer);
    }
    toastTimer = setTimeout(() => { box.className = 'toast hidden'; }, isError ? 8000 : 3000);
  }

  function showResult(targetId, value, isError) {
    const target = $(targetId);
    if (typeof value === 'string') {
      target.textContent = value;
    } else {
      target.textContent = JSON.stringify(value, null, 2);
    }
    target.className = 'result' + (isError ? ' error' : ' ok');
  }

  /** Executes a host command with busy indicator; errors are shown in the given result box (or as toast). */
  async function run(label, command, args, resultTargetId) {
    $('busyText').textContent = label + '\u2026';
    $('busy').classList.remove('hidden');
    try {
      const result = await callHost(command, args);
      if (resultTargetId) {
        showResult(resultTargetId, result, false);
      }
      return result;
    } catch (error) {
      if (resultTargetId) {
        showResult(resultTargetId, error.message, true);
      } else {
        toast(error.message, true);
      }
      return undefined;
    } finally {
      $('busy').classList.add('hidden');
    }
  }

  // ======================================================================
  //  AuthTokenConfig schema (drives the config editor)
  // ======================================================================

  const configSchema = [
    {
      group: 'Display', fields: [
        { name: 'DisplayLabel', type: 'text' },
        { name: 'DisplayIconUrl', type: 'text' }
      ]
    },
    {
      group: 'Issuing', fields: [
        { name: 'IssueMode', type: 'mode', options: 'issueModes' },
        { name: 'ClientId', type: 'text' },
        { name: 'ClientSecret', type: 'secret' },
        { name: 'AuthEndpointUrl', type: 'text', desc: 'OAuth authorize endpoint' },
        { name: 'RetrieveEndpointUrl', type: 'text', desc: 'OAuth token endpoint (or HTTP_GET url)' },
        { name: 'RetrieveEndpointAuthorization', type: 'text' },
        { name: 'AuthEndpointRejectsIframe', type: 'bool' },
        { name: 'AdditionalAuthArgs', type: 'dict' },
        { name: 'AdditionalRetrieveArgs', type: 'dict' }
      ]
    },
    {
      group: 'Local logon / JWT generation', fields: [
        { name: 'JwtSelfSignKey', type: 'secret' },
        { name: 'JwtSelfSignAlg', type: 'mode', options: 'jwsAlgorithms' },
        { name: 'JwtExpMinutes', type: 'int' },
        { name: 'LocalLogonNameToLower', type: 'bool' },
        { name: 'LocalLogonNamePersistation', type: 'text' },
        { name: 'LocalLogonNameSyntax', type: 'text' },
        { name: 'LocalLogonNameInputLabel', type: 'text' },
        { name: 'LocalLogonPassInputLabel', type: 'text' },
        { name: 'LocalLogonSaltDisplayLabel', type: 'text' }
      ]
    },
    {
      group: 'Validation', fields: [
        { name: 'ValidationMode', type: 'mode', options: 'validationModes' },
        { name: 'JwtValidationKey', type: 'secret' },
        { name: 'ValidationEndpointUrl', type: 'text', desc: 'OAuth introspection endpoint' },
        { name: 'validationEndpointAuthorization', type: 'text' },
        { name: 'ValidationOutcomeCacheMins', type: 'int' },
        { name: 'ClaimValidationIgnoresCasing', type: 'bool' },
        { name: 'Claims', type: 'dict', desc: 'claims to add (issuing) / to enforce (validation)' }
      ]
    }
  ];

  const oauthSchema = [
    { name: 'ProviderType', type: 'mode', options: 'providerTypes' },
    { name: 'GrantType', type: 'mode', optionValues: ['code', 'implicit'] },
    { name: 'RedirectUri', type: 'text' },
    { name: 'Scopes', type: 'text', desc: 'space separated' },
    { name: 'State', type: 'text', desc: 'random if empty' },
    { name: 'RequestRefreshToken', type: 'bool' },
    { name: 'RequestIdToken', type: 'bool' },
    { name: 'TryKeepBrowserInvisible', type: 'bool' },
    { name: 'ProviderConfiguration', type: 'dict', desc: 'raw IOAuthOperationsProvider values (override), e.g. userinfo_endpoint, client_credentials_via_basicauth, introspection_auth' }
  ];

  // ======================================================================
  //  state
  // ======================================================================

  let appState = null;
  let editedProfile = null;
  let editedOriginalName = null;
  let isDirty = false;

  function setDirty(dirty) {
    isDirty = dirty;
    $('dirtyMarker').classList.toggle('hidden', !dirty);
  }

  function findProfile(name) {
    return appState.profiles.find((p) => p.Name.toLowerCase() === (name || '').toLowerCase());
  }

  function applyState(state) {
    appState = state;
    $('settingsPath').textContent = 'Stored per user in: ' + state.settingsFilePath;
    renderProfileList();
  }

  // ======================================================================
  //  profile list
  // ======================================================================

  function renderProfileList() {
    const list = $('profileList');
    list.innerHTML = '';
    appState.profiles.forEach((profile) => {
      const item = el('li', profile.Name === appState.currentProfileName ? 'selected' : '');
      item.appendChild(el('span', '', profile.Name));
      const config = profile.Config || {};
      item.appendChild(el('span', 'sub', (config.IssueMode || '-') + ' / ' + (config.ValidationMode || '-')));
      item.addEventListener('click', () => selectProfile(profile.Name));
      list.appendChild(item);
    });
  }

  function selectProfile(name) {
    if (isDirty && editedOriginalName !== name) {
      if (!confirm('Discard unsaved changes of "' + editedOriginalName + '"?')) {
        return;
      }
    }
    const profile = findProfile(name);
    if (!profile) {
      return;
    }
    appState.currentProfileName = profile.Name;
    callHost('selectProfile', { name: profile.Name });
    loadIntoEditor(profile);
    renderProfileList();
  }

  function loadIntoEditor(profile) {
    editedProfile = clone(profile);
    editedOriginalName = profile.Name;
    if (!editedProfile.Config) {
      editedProfile.Config = clone(appState.defaultConfig);
    }
    if (!editedProfile.OAuth) {
      editedProfile.OAuth = {};
    }
    $('profileName').value = editedProfile.Name;
    renderConfigEditor();
    refreshRawJson();
    syncJwtTab();
    setDirty(false);
  }

  // ======================================================================
  //  config editor
  // ======================================================================

  function createInput(field, target, onChange) {
    const value = target[field.name];

    if (field.type === 'bool') {
      const row = el('label', 'check-row');
      const checkbox = el('input');
      checkbox.type = 'checkbox';
      checkbox.checked = !!value;
      checkbox.addEventListener('change', () => { target[field.name] = checkbox.checked; onChange(); });
      row.appendChild(checkbox);
      row.appendChild(document.createTextNode(field.name));
      return row;
    }

    const label = el('label', '', field.name);

    if (field.type === 'dict') {
      label.appendChild(createDictEditor(target, field.name, onChange));
    } else if (field.type === 'mode') {
      const input = el('input');
      input.type = 'text';
      const listId = 'list_' + field.name;
      input.setAttribute('list', listId);
      input.value = value === null || value === undefined ? '' : value;
      const datalist = el('datalist');
      datalist.id = listId;
      const options = field.optionValues || appState[field.options] || [];
      options.forEach((option) => {
        const optionElement = el('option');
        optionElement.value = option;
        datalist.appendChild(optionElement);
      });
      input.addEventListener('input', () => { target[field.name] = input.value === '' ? null : input.value; onChange(); });
      label.appendChild(input);
      label.appendChild(datalist);
    } else {
      const input = el('input');
      input.type = field.type === 'int' ? 'number' : (field.type === 'secret' ? 'password' : 'text');
      input.value = value === null || value === undefined ? '' : value;
      if (field.type === 'secret') {
        input.addEventListener('focus', () => { input.type = 'text'; });
        input.addEventListener('blur', () => { input.type = 'password'; });
      }
      input.addEventListener('input', () => {
        if (field.type === 'int') {
          target[field.name] = parseInt(input.value, 10) || 0;
        } else {
          target[field.name] = input.value === '' ? null : input.value;
        }
        onChange();
      });
      label.appendChild(input);
    }

    if (field.desc) {
      label.appendChild(el('div', 'field-desc', field.desc));
    }
    return label;
  }

  function createDictEditor(target, propertyName, onChange) {
    const wrapper = el('div');
    const table = el('table', 'kv-table');
    wrapper.appendChild(table);

    function readRows() {
      const result = {};
      let hasEntries = false;
      table.querySelectorAll('tr').forEach((row) => {
        const inputs = row.querySelectorAll('input');
        const key = inputs[0].value.trim();
        if (key !== '') {
          result[key] = inputs[1].value;
          hasEntries = true;
        }
      });
      target[propertyName] = hasEntries ? result : (propertyName === 'ProviderConfiguration' ? {} : null);
      onChange();
    }

    function addRow(key, value) {
      const row = el('tr');
      const keyCell = el('td');
      const keyInput = el('input');
      keyInput.placeholder = 'key';
      keyInput.value = key;
      keyInput.addEventListener('input', readRows);
      keyCell.appendChild(keyInput);
      const valueCell = el('td');
      const valueInput = el('input');
      valueInput.placeholder = 'value';
      valueInput.value = value === null || value === undefined ? '' : value;
      valueInput.addEventListener('input', readRows);
      valueCell.appendChild(valueInput);
      const removeCell = el('td');
      const removeButton = el('button', 'danger', '\u2715');
      removeButton.addEventListener('click', (e) => { e.preventDefault(); row.remove(); readRows(); });
      removeCell.appendChild(removeButton);
      row.appendChild(keyCell);
      row.appendChild(valueCell);
      row.appendChild(removeCell);
      table.appendChild(row);
      return keyInput;
    }

    const existing = target[propertyName] || {};
    Object.keys(existing).forEach((key) => addRow(key, existing[key]));

    const addButton = el('button', '', '+ add entry');
    addButton.addEventListener('click', (e) => { e.preventDefault(); addRow('', '').focus(); });
    wrapper.appendChild(addButton);
    return wrapper;
  }

  function onEditorChanged() {
    setDirty(true);
    refreshRawJson();
  }

  function renderConfigEditor() {
    const page = $('tab-config');
    page.innerHTML = '';

    const knownNames = new Set();
    configSchema.forEach((group) => {
      const fieldset = el('fieldset');
      fieldset.appendChild(el('legend', '', group.group));
      const grid = el('div', 'grid2');
      group.fields.forEach((field) => {
        knownNames.add(field.name);
        grid.appendChild(createInput(field, editedProfile.Config, onEditorChanged));
      });
      fieldset.appendChild(grid);
      page.appendChild(fieldset);
    });

    //properties of the AuthTokenConfig, which are not (yet) known by this editor
    const unknownFields = Object.keys(appState.defaultConfig)
      .concat(Object.keys(editedProfile.Config))
      .filter((name, index, all) => !knownNames.has(name) && all.indexOf(name) === index);
    if (unknownFields.length > 0) {
      const fieldset = el('fieldset');
      fieldset.appendChild(el('legend', '', 'Other'));
      const grid = el('div', 'grid2');
      unknownFields.forEach((name) => {
        const sample = editedProfile.Config[name] !== undefined ? editedProfile.Config[name] : appState.defaultConfig[name];
        let type = 'text';
        if (typeof sample === 'boolean') {
          type = 'bool';
        } else if (typeof sample === 'number') {
          type = 'int';
        } else if (sample !== null && typeof sample === 'object') {
          type = 'dict';
        }
        grid.appendChild(createInput({ name: name, type: type }, editedProfile.Config, onEditorChanged));
      });
      fieldset.appendChild(grid);
      page.appendChild(fieldset);
    }

    const oauthFieldset = el('fieldset');
    oauthFieldset.appendChild(el('legend', '', 'OAuth flow settings (test client only, not part of AuthTokenConfig)'));
    const oauthGrid = el('div', 'grid2');
    oauthSchema.forEach((field) => {
      oauthGrid.appendChild(createInput(field, editedProfile.OAuth, onEditorChanged));
    });
    oauthFieldset.appendChild(oauthGrid);
    page.appendChild(oauthFieldset);
  }

  // ======================================================================
  //  raw json
  // ======================================================================

  function currentProfileForHost() {
    const profile = clone(editedProfile);
    profile.Name = $('profileName').value.trim() || editedOriginalName;
    return profile;
  }

  function refreshRawJson() {
    $('rawJson').value = JSON.stringify(currentProfileForHost(), null, 2);
  }

  function applyRawJson() {
    let parsed;
    try {
      parsed = JSON.parse($('rawJson').value);
    } catch (error) {
      toast('Invalid JSON: ' + error.message, true);
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      toast('The JSON must be a single profile object.', true);
      return;
    }
    if (!parsed.Config) {
      //a bare AuthTokenConfig was pasted
      parsed = { Name: $('profileName').value, Config: parsed, OAuth: editedProfile.OAuth };
    }
    editedProfile = parsed;
    if (!editedProfile.OAuth) {
      editedProfile.OAuth = {};
    }
    $('profileName').value = editedProfile.Name || editedOriginalName;
    renderConfigEditor();
    syncJwtTab();
    setDirty(true);
    toast('JSON applied to the editor (not yet saved).');
  }

  // ======================================================================
  //  profile commands
  // ======================================================================

  async function saveProfile() {
    const profile = currentProfileForHost();
    const state = await run('Saving', 'saveProfile', { profile: profile, oldName: editedOriginalName });
    if (state) {
      applyState(state);
      loadIntoEditor(findProfile(profile.Name));
      toast('Saved "' + profile.Name + '".');
    }
  }

  function uniqueName(base) {
    let candidate = base;
    let counter = 2;
    while (findProfile(candidate)) {
      candidate = base + ' (' + counter + ')';
      counter++;
    }
    return candidate;
  }

  async function createProfile(template) {
    const profile = template ? clone(template) : { Config: clone(appState.defaultConfig), OAuth: {} };
    profile.Name = uniqueName(template ? template.Name + ' - Copy' : 'New Profile');
    const state = await run('Creating', 'saveProfile', { profile: profile, oldName: null });
    if (state) {
      applyState(state);
      loadIntoEditor(findProfile(profile.Name));
    }
  }

  async function deleteProfile() {
    if (!confirm('Delete profile "' + editedOriginalName + '"?')) {
      return;
    }
    const state = await run('Deleting', 'deleteProfile', { name: editedOriginalName });
    if (state) {
      setDirty(false);
      applyState(state);
      loadIntoEditor(findProfile(state.currentProfileName));
    }
  }

  async function importProfiles() {
    const state = await run('Importing', 'importProfiles', {});
    if (state) {
      applyState(state);
      if (state.importedNames && state.importedNames.length > 0) {
        loadIntoEditor(findProfile(state.currentProfileName));
        toast('Imported: ' + state.importedNames.join(', '));
      }
    }
  }

  async function exportProfiles(all) {
    if (!all && isDirty) {
      toast('Please save the profile before exporting it.', true);
      return;
    }
    const names = all ? [] : [editedOriginalName];
    const path = await run('Exporting', 'exportProfiles', { names: names });
    if (path) {
      toast('Exported to ' + path);
    }
  }

  // ======================================================================
  //  tokens
  // ======================================================================

  function currentTokens() {
    return {
      AccessToken: $('tokAccess').value.trim(),
      RefreshToken: $('tokRefresh').value.trim(),
      IdToken: $('tokId').value.trim()
    };
  }

  function setTokens(tokens) {
    $('tokAccess').value = tokens.AccessToken || '';
    $('tokRefresh').value = tokens.RefreshToken || '';
    $('tokId').value = tokens.IdToken || '';
    callHost('saveTokens', { tokens: currentTokens() });
    decodeToken('tokAccess');
  }

  /** Takes over the tokens of a 'TokenIssuingResult' reply (if successful). */
  function takeOverTokenResult(reply) {
    if (!reply || !reply.result) {
      return;
    }
    const result = reply.result;
    if (reply.success && result.access_token) {
      setTokens({
        AccessToken: result.access_token,
        RefreshToken: result.refresh_token || $('tokRefresh').value,
        IdToken: result.id_token || ''
      });
    }
  }

  async function decodeToken(sourceId) {
    const token = $(sourceId).value.trim();
    if (token === '') {
      $('tokDecoded').textContent = '';
      return;
    }
    try {
      const decoded = await callHost('decodeJwt', { token: token });
      showResult('tokDecoded', decoded, false);
    } catch (error) {
      showResult('tokDecoded', error.message, true);
    }
  }

  // ======================================================================
  //  factories & local jwt
  // ======================================================================

  function syncJwtTab() {
    const config = editedProfile.Config;
    const algSelect = $('jwtAlg');
    if (algSelect.options.length === 0) {
      appState.jwsAlgorithms.forEach((alg) => {
        const option = el('option', '', alg);
        option.value = alg;
        algSelect.appendChild(option);
      });
    }
    $('jwtKey').value = config.JwtSelfSignKey || '';
    $('jwtAlg').value = appState.jwsAlgorithms.indexOf(config.JwtSelfSignAlg) >= 0 ? config.JwtSelfSignAlg : 'HS256';
    $('jwtExp').value = config.JwtExpMinutes || 60;
  }

  function buildLocalJwtConfig() {
    const config = clone(editedProfile.Config);
    config.IssueMode = 'LOCAL_JWT_GENERATION';
    config.JwtSelfSignKey = $('jwtKey').value;
    config.JwtSelfSignAlg = $('jwtAlg').value;
    config.JwtExpMinutes = parseInt($('jwtExp').value, 10) || 60;
    //the factory currently requires a 'JwtValidationKey' also for issuing
    if (!config.JwtValidationKey) {
      config.JwtValidationKey = config.JwtSelfSignKey;
    }
    return config;
  }

  function buildLocalValidationConfig() {
    const config = clone(editedProfile.Config);
    config.ValidationMode = 'LOCAL_JWT_VALIDATION';
    if (!config.JwtValidationKey) {
      config.JwtValidationKey = $('jwtKey').value;
    }
    return config;
  }

  async function issueViaFactory(config, subjectId, audienceId, scopesId, claimsId, resultId) {
    const reply = await run('Issuing', 'issueToken', {
      config: config,
      subject: $(subjectId).value,
      audience: $(audienceId).value,
      scopes: $(scopesId).value,
      claimsJson: $(claimsId).value
    }, resultId);
    takeOverTokenResult(reply);
  }

  // ======================================================================
  //  oauth
  // ======================================================================

  async function oauth(label, command, extraArgs) {
    const args = Object.assign({ profile: currentProfileForHost() }, extraArgs || {});
    const reply = await run(label, command, args, 'oauthResult');
    takeOverTokenResult(reply);
    return reply;
  }

  // ======================================================================
  //  wiring
  // ======================================================================

  function wireTabs() {
    document.querySelectorAll('#tabs button').forEach((button) => {
      button.addEventListener('click', () => {
        document.querySelectorAll('#tabs button').forEach((b) => b.classList.remove('active'));
        button.classList.add('active');
        document.querySelectorAll('.tab-page').forEach((page) => page.classList.add('hidden'));
        $('tab-' + button.dataset.tab).classList.remove('hidden');
        if (button.dataset.tab === 'json') {
          refreshRawJson();
        }
      });
    });
  }

  function wireButtons() {
    $('btnNewProfile').addEventListener('click', () => createProfile(null));
    $('btnCloneProfile').addEventListener('click', () => createProfile(currentProfileForHost()));
    $('btnDeleteProfile').addEventListener('click', deleteProfile);
    $('btnImport').addEventListener('click', importProfiles);
    $('btnExport').addEventListener('click', () => exportProfiles(false));
    $('btnExportAll').addEventListener('click', () => exportProfiles(true));
    $('btnSave').addEventListener('click', saveProfile);
    $('btnRevert').addEventListener('click', () => loadIntoEditor(findProfile(editedOriginalName)));
    $('profileName').addEventListener('input', onEditorChanged);

    $('btnApplyJson').addEventListener('click', applyRawJson);
    $('btnReloadJson').addEventListener('click', refreshRawJson);
    $('btnCopyConfigJson').addEventListener('click', () => {
      callHost('copyToClipboard', { text: JSON.stringify(editedProfile.Config, null, 2) });
      toast('AuthTokenConfig copied to clipboard.');
    });

    $('btnDescribeIssuer').addEventListener('click', () => run('Initializing issuer', 'describeIssuer', { config: editedProfile.Config }, 'factoryResult'));
    $('btnDescribeIntrospector').addEventListener('click', () => run('Initializing introspector', 'describeIntrospector', { config: editedProfile.Config }, 'factoryResult'));
    $('btnIssue').addEventListener('click', () => issueViaFactory(editedProfile.Config, 'issueSubject', 'issueAudience', 'issueScopes', 'issueClaims', 'factoryResult'));
    $('btnIntrospect').addEventListener('click', () => run('Introspecting', 'introspectToken', { config: editedProfile.Config, token: $('tokAccess').value }, 'factoryResult'));

    $('btnJwtIssue').addEventListener('click', () => issueViaFactory(buildLocalJwtConfig(), 'jwtSubject', 'jwtAudience', 'jwtScopes', 'jwtClaims', 'jwtResult'));
    $('btnJwtValidate').addEventListener('click', () => run('Validating', 'introspectToken', { config: buildLocalValidationConfig(), token: $('tokAccess').value }, 'jwtResult'));
    $('btnJwtTakeOver').addEventListener('click', () => {
      editedProfile.Config.JwtSelfSignKey = $('jwtKey').value;
      editedProfile.Config.JwtSelfSignAlg = $('jwtAlg').value;
      editedProfile.Config.JwtExpMinutes = parseInt($('jwtExp').value, 10) || 60;
      renderConfigEditor();
      onEditorChanged();
      toast('Taken over into the config editor (not yet saved).');
    });

    $('btnOAuthInteractive').addEventListener('click', () => oauth('Waiting for interactive login', 'oauthInteractive'));
    $('btnOAuthUrl').addEventListener('click', async () => {
      const url = await run('Generating', 'oauthAuthorizeUrl', { profile: currentProfileForHost() }, 'oauthResult');
      if (url) {
        $('oauthAuthorizeUrl').value = url;
      }
    });
    $('btnOAuthOpenUrl').addEventListener('click', () => run('Opening browser', 'openBrowser', { url: $('oauthAuthorizeUrl').value.trim() }));
    $('btnOAuthFromUrl').addEventListener('click', () => oauth('Retrieving token', 'oauthFromRedirectedUrl', { url: $('oauthRedirectedUrl').value.trim() }));
    $('btnOAuthExchange').addEventListener('click', () => oauth('Exchanging code', 'oauthExchangeCode', { code: $('oauthCode').value.trim() }));
    $('btnOAuthClientCredentials').addEventListener('click', () => oauth('Client credentials flow', 'oauthClientCredentials'));
    $('btnOAuthRefresh').addEventListener('click', () => oauth('Refreshing', 'oauthRefresh', { refreshToken: $('tokRefresh').value.trim() }));
    $('btnOAuthDescribe').addEventListener('click', () => run('Creating provider', 'describeProvider', { profile: currentProfileForHost() }, 'oauthResult'));
    $('btnOAuthValidate').addEventListener('click', () => run('Validating', 'oauthValidate', { profile: currentProfileForHost(), token: $('tokAccess').value }, 'oauthResult'));
    $('btnOAuthSubject').addEventListener('click', () => run('Resolving', 'oauthResolveSubject', { profile: currentProfileForHost(), token: $('tokAccess').value, idToken: $('tokId').value }, 'oauthResult'));

    $('btnClearTokens').addEventListener('click', () => setTokens({}));
    ['tokAccess', 'tokRefresh', 'tokId'].forEach((id) => {
      $(id).addEventListener('change', () => {
        callHost('saveTokens', { tokens: currentTokens() });
        if (id !== 'tokRefresh') {
          decodeToken(id);
        }
      });
    });
    document.querySelectorAll('[data-copy]').forEach((button) => {
      button.addEventListener('click', () => {
        callHost('copyToClipboard', { text: $(button.dataset.copy).value });
        toast('Copied.');
      });
    });
    document.querySelectorAll('[data-decode]').forEach((button) => {
      button.addEventListener('click', () => decodeToken(button.dataset.decode));
    });

    document.addEventListener('keydown', (e) => {
      if (e.ctrlKey && (e.key === 's' || e.key === 'S')) {
        e.preventDefault();
        saveProfile();
      }
    });
  }

  async function init() {
    wireTabs();
    wireButtons();
    const state = await callHost('getState', {});
    applyState(state);
    loadIntoEditor(findProfile(state.currentProfileName));
    $('tokAccess').value = state.lastTokens.AccessToken || '';
    $('tokRefresh').value = state.lastTokens.RefreshToken || '';
    $('tokId').value = state.lastTokens.IdToken || '';
    decodeToken('tokAccess');
  }

  init().catch((error) => toast(error.message, true));

})();
