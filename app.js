    (function () {
      'use strict';

      /* ----------------------------------------------------------
         1. MOBILE KEYBOARD & VISUAL VIEWPORT LOCK
         Ensures the top header NEVER scrolls away when keyboard opens
      ---------------------------------------------------------- */
      const appShell = document.getElementById('app-viewport-shell');
      const chatStream = document.getElementById('chat-stream');
      const gameStageSection = document.getElementById('game-stage-section');
      let isKeyboardOpen = false;
      let userManuallyCollapsedStage = false;

      function syncVisualViewport() {
        if (window.visualViewport) {
          const vv = window.visualViewport;
          document.documentElement.style.setProperty('--vvh', `${vv.height}px`);
          document.documentElement.style.setProperty('--vv-top', `${vv.offsetTop}px`);

          // Detect if virtual keyboard is open (viewport height shrunk by > 140px)
          const heightDiff = window.innerHeight - vv.height;
          const nowKeyboardOpen = heightDiff > 140;

          if (nowKeyboardOpen !== isKeyboardOpen) {
            isKeyboardOpen = nowKeyboardOpen;
            if (isKeyboardOpen) {
              // Automatically compact the game stage while typing so header + chat + input fit effortlessly
              gameStageSection.classList.add('hidden');
            } else if (!userManuallyCollapsedStage) {
              gameStageSection.classList.remove('hidden');
            }
            scrollToBottom(false);
          }
        } else {
          document.documentElement.style.setProperty('--vvh', `${window.innerHeight}px`);
          document.documentElement.style.setProperty('--vv-top', `0px`);
        }
        window.scrollTo(0, 0);
      }

      if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', syncVisualViewport);
        window.visualViewport.addEventListener('scroll', syncVisualViewport);
      }
      window.addEventListener('resize', syncVisualViewport);
      syncVisualViewport();

      /* ----------------------------------------------------------
         2. END-TO-END SECURITY ENGINE (Web Crypto API AES-GCM 256)
         Transparent protection for all messages, cards, and images
      ---------------------------------------------------------- */
      const CryptoEngine = {
        key: null,
        myKeyPair: null,

        // Derive a room key from the 10-character code + optional ECDH shared bits
        async initRoomKey(roomCode, sharedSecretBytes = null) {
          const enc = new TextEncoder();
          const baseMaterial = sharedSecretBytes
            ? await crypto.subtle.importKey('raw', sharedSecretBytes, 'HKDF', false, ['deriveKey'])
            : await crypto.subtle.importKey('raw', enc.encode(`TOD-SKETCH-${roomCode}-SECRET`), 'PBKDF2', false, ['deriveKey']);

          if (sharedSecretBytes) {
            this.key = await crypto.subtle.deriveKey(
              {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: enc.encode(`NOTEBOOK-SALT-${roomCode}`),
                info: enc.encode('TOD-2PLAYER-CHANNEL')
              },
              baseMaterial,
              { name: 'AES-GCM', length: 256 },
              false,
              ['encrypt', 'decrypt']
            );
          } else {
            this.key = await crypto.subtle.deriveKey(
              {
                name: 'PBKDF2',
                salt: enc.encode(`NOTEBOOK-SALT-${roomCode}`),
                iterations: 25000,
                hash: 'SHA-256'
              },
              baseMaterial,
              { name: 'AES-GCM', length: 256 },
              false,
              ['encrypt', 'decrypt']
            );
          }
        },

        async generateEcdhPublicJwk() {
          this.myKeyPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits']
          );
          return await crypto.subtle.exportKey('jwk', this.myKeyPair.publicKey);
        },

        async completeEcdhHandshake(partnerPublicJwk, roomCode) {
          try {
            const partnerPubKey = await crypto.subtle.importKey(
              'jwk',
              partnerPublicJwk,
              { name: 'ECDH', namedCurve: 'P-256' },
              false,
              []
            );
            const sharedBits = await crypto.subtle.deriveBits(
              { name: 'ECDH', public: partnerPubKey },
              this.myKeyPair.privateKey,
              256
            );
            await this.initRoomKey(roomCode, sharedBits);
          } catch (err) {
            console.warn('Fallback to room-derived key:', err);
          }
        },

         uint8ToBase64(bytes) {
          let binary = '';
          const len = bytes.byteLength;
          for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
          }
          return btoa(binary);
        },

        base64ToUint8(base64) {
          const binary = atob(base64);
          const len = binary.length;
          const bytes = new Uint8Array(len);
          for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
          }
          return bytes;
        },

        async encryptPayload(obj) {
          if (!this.key) return null;
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const encoded = new TextEncoder().encode(JSON.stringify(obj));
          const cipherBuffer = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.key,
            encoded
          );
          return {
            iv: this.uint8ToBase64(iv),
            ct: this.uint8ToBase64(new Uint8Array(cipherBuffer))
          };
        },

        async decryptPayload(packet) {
          if (!this.key || !packet || !packet.iv || !packet.ct) return null;
          const iv = this.base64ToUint8(packet.iv);
          const ct = this.base64ToUint8(packet.ct);
          const plainBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.key,
            ct
          );
          const decoded = new TextDecoder().decode(plainBuffer);
          return JSON.parse(decoded);
        }
      };

      /* ----------------------------------------------------------
         3. APPLICATION STATE & PERSISTENCE (Survives Minimize / Reload)
      ---------------------------------------------------------- */
      const STORAGE_KEY = 'tod_sketch_session_v1';
      const DEFAULT_DECK = [
        { id: 'd1', type: 'truth', text: 'What is the funniest childhood memory you still laugh about?' },
        { id: 'd2', type: 'truth', text: 'If we could travel anywhere tomorrow, where would you pick?' },
        { id: 'd3', type: 'truth', text: 'What is a secret talent or weird skill you have?' },
        { id: 'd4', type: 'truth', text: 'What was your very first impression of me?' },
        { id: 'd5', type: 'truth', text: 'What is the most embarrassing song on your playlist?' },
        { id: 'd6', type: 'dare', text: 'Draw a funny doodle on paper or make a silly face and send a photo!' },
        { id: 'd7', type: 'dare', text: 'Turn on your mic and speak in a cartoon voice for the next 30 seconds!' },
        { id: 'd8', type: 'dare', text: 'Send a photo of the weirdest or coolest object near you right now.' },
        { id: 'd9', type: 'dare', text: 'Sing the chorus of your favorite song on voice chat or type it dramatically!' },
        { id: 'd10', type: 'dare', text: 'Compliment your friend using only food comparisons!' }
      ];

      const state = {
        playerToken: '',
        myName: '',
        myAvatar: 'fox',
        role: null, // 'host' | 'guest'
        roomCode: '', // Strictly 10 characters
        partnerName: 'Waiting for friend...',
        partnerAvatar: 'waiting',
        partnerToken: null,
        partnerOnline: false,
        partnerMicOn: false,
        partnerTyping: false,
        partnerExplicitlyLeft: false,
        myMicOn: false,
        scores: { me: 0, partner: 0 },
        turn: 'me', // 'me' | 'partner'
        gamePhase: 'pick', // 'pick' | 'compose' | 'card'
        selectedType: 'truth', // 'truth' | 'dare'
        activeCard: null, // { type, text, target: 'me'|'partner', authorName }
        customDeck: [...DEFAULT_DECK],
        deckFilter: 'all',
        chatHistory: []
      };

      // Generate or restore unique player token so reconnections after browser minimize are recognized
      function initPlayerToken() {
        let savedToken = sessionStorage.getItem('tod_player_token');
        if (!savedToken) {
          const arr = new Uint8Array(8);
          crypto.getRandomValues(arr);
          savedToken = Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
          sessionStorage.setItem('tod_player_token', savedToken);
        }
        state.playerToken = savedToken;
      }
      initPlayerToken();

      function saveSessionState() {
        if (!state.roomCode) return;
        try {
          const snapshot = {
            myName: state.myName,
            myAvatar: state.myAvatar,
            role: state.role,
            roomCode: state.roomCode,
            partnerName: state.partnerName,
            partnerAvatar: state.partnerAvatar,
            partnerToken: state.partnerToken,
            scores: state.scores,
            turn: state.turn,
            gamePhase: state.gamePhase,
            selectedType: state.selectedType,
            activeCard: state.activeCard,
            customDeck: state.customDeck,
            chatHistory: state.chatHistory.slice(-40)
          };
          sessionStorage.setItem(STORAGE_KEY, JSON.stringify(snapshot));
        } catch (e) {
          console.warn('Could not save session snapshot:', e);
        }
      }

      function clearSessionState() {
        sessionStorage.removeItem(STORAGE_KEY);
      }

      /* ----------------------------------------------------------
         4. UI ELEMENTS & HELPERS
      ---------------------------------------------------------- */
      const el = {
        lobbyScreen: document.getElementById('lobby-screen'),
        roomScreen: document.getElementById('room-screen'),
        avatarPicker: document.getElementById('avatar-picker'),
        playerNameInput: document.getElementById('player-name-input'),
        createRoomBtn: document.getElementById('create-room-btn'),
        joinCodeInput: document.getElementById('join-code-input'),
        codeCharCounter: document.getElementById('code-char-counter'),
        joinRoomBtn: document.getElementById('join-room-btn'),

        // Header
        partnerAvatarBox: document.getElementById('partner-avatar-box'),
        partnerOnlineDot: document.getElementById('partner-online-dot'),
        partnerNameDisplay: document.getElementById('partner-name-display'),
        partnerMicBadge: document.getElementById('partner-mic-badge'),
        partnerMicIcon: document.getElementById('partner-mic-icon'),
        partnerStatusText: document.getElementById('partner-status-text'),
        headerTypingBadge: document.getElementById('header-typing-badge'),
        copyCodePill: document.getElementById('copy-code-pill'),
        headerRoomCode: document.getElementById('header-room-code'),
        micToggleBtn: document.getElementById('mic-toggle-btn'),
        myMicIcon: document.getElementById('my-mic-icon'),
        myMicSlash: document.getElementById('my-mic-slash'),
        toggleStageBtn: document.getElementById('toggle-stage-btn'),
        leaveRoomBtn: document.getElementById('leave-room-btn'),
        connectionBanner: document.getElementById('connection-banner'),
        bannerSpinner: document.getElementById('banner-spinner'),
        bannerText: document.getElementById('banner-text'),
        bannerShareBtn: document.getElementById('banner-share-btn'),

        // Game Stage
        turnIndicatorPill: document.getElementById('turn-indicator-pill'),
        spinPencilBtn: document.getElementById('spin-pencil-btn'),
        scoreDisplay: document.getElementById('score-display'),
        openCustomDeckBtn: document.getElementById('open-custom-deck-btn'),
        stagePickMode: document.getElementById('stage-pick-mode'),
        stagePickTitle: document.getElementById('stage-pick-title'),
        chooseTruthBtn: document.getElementById('choose-truth-btn'),
        chooseDareBtn: document.getElementById('choose-dare-btn'),
        stageComposePrompt: document.getElementById('stage-compose-prompt'),
        composeBadge: document.getElementById('compose-badge'),
        randomSavedPromptBtn: document.getElementById('random-saved-prompt-btn'),
        cancelComposeBtn: document.getElementById('cancel-compose-btn'),
        customPromptInput: document.getElementById('custom-prompt-input'),
        sendPromptCardBtn: document.getElementById('send-prompt-card-btn'),
        stageActiveCard: document.getElementById('stage-active-card'),
        activeCardBadge: document.getElementById('active-card-badge'),
        activeCardTarget: document.getElementById('active-card-target'),
        activeCardText: document.getElementById('active-card-text'),
        skipCardBtn: document.getElementById('skip-card-btn'),
        completeCardBtn: document.getElementById('complete-card-btn'),

        // Chat & Footer
        chatTypingRow: document.getElementById('chat-typing-row'),
        chatTypingLabel: document.getElementById('chat-typing-label'),
        chatForm: document.getElementById('chat-form'),
        imageUploadInput: document.getElementById('image-upload-input'),
        sharePhotoBtn: document.getElementById('share-photo-btn'),
        chatMessageInput: document.getElementById('chat-message-input'),

        // Modals
        customDeckModal: document.getElementById('custom-deck-modal'),
        closeDeckModalBtn: document.getElementById('close-deck-modal-btn'),
        newDeckType: document.getElementById('new-deck-type'),
        newDeckText: document.getElementById('new-deck-text'),
        addToDeckBtn: document.getElementById('add-to-deck-btn'),
        deckListContainer: document.getElementById('deck-list-container'),
        photoLightboxModal: document.getElementById('photo-lightbox-modal'),
        lightboxImg: document.getElementById('lightbox-img'),
        lightboxCaption: document.getElementById('lightbox-caption'),
        closeLightboxBtn: document.getElementById('close-lightbox-btn'),
        leaveConfirmModal: document.getElementById('leave-confirm-modal'),
        cancelLeaveBtn: document.getElementById('cancel-leave-btn'),
        confirmLeaveBtn: document.getElementById('confirm-leave-btn'),
        toastContainer: document.getElementById('toast-container'),
        remoteAudio: document.getElementById('remote-audio')
      };

      function showToast(message, icon = '✨', bg = '#FFE46B') {
        const toast = document.createElement('div');
        toast.className = 'sketch-pill px-3.5 py-1.5 text-xs font-ui font-semibold text-[#2B2623] flex items-center gap-1.5 animate-pop pointer-events-auto';
        toast.style.backgroundColor = bg;
        toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;
        el.toastContainer.appendChild(toast);
        setTimeout(() => {
          toast.style.opacity = '0';
          toast.style.transition = 'opacity 0.25s ease';
          setTimeout(() => toast.remove(), 260);
        }, 2800);
      }

      function escapeHtml(str) {
        return String(str || '')
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;');
      }

      // Hand-drawn SVG Doodle Avatar Library (Never clips on any browser or font)
      const DOODLE_AVATAR_SVGS = {
        fox: `<svg class="w-full h-full overflow-visible" viewBox="0 0 36 36" fill="none"><path d="M6 8L13 15L23 15L30 8L28 24C28 28 23.5 31 18 31C12.5 31 8 28 8 24L6 8Z" fill="#FF9F68" stroke="#2B2623" stroke-width="2.4" stroke-linejoin="round"/><path d="M8 23C11 23 14 26 18 29C22 26 25 23 28 23C27 28 23 31 18 31C13 31 9 28 8 23Z" fill="#FFFDF9" stroke="#2B2623" stroke-width="2" stroke-linejoin="round"/><circle cx="13.5" cy="20" r="1.7" fill="#2B2623"/><circle cx="22.5" cy="20" r="1.7" fill="#2B2623"/><ellipse cx="18" cy="25" rx="2.2" ry="1.6" fill="#2B2623"/></svg>`,
        panda: `<svg class="w-full h-full overflow-visible" viewBox="0 0 36 36" fill="none"><circle cx="9" cy="10" r="4.5" fill="#2B2623"/><circle cx="27" cy="10" r="4.5" fill="#2B2623"/><circle cx="18" cy="20" r="11" fill="#FFFDF9" stroke="#2B2623" stroke-width="2.4"/><ellipse cx="13.5" cy="19.5" rx="3.2" ry="2.6" transform="rotate(-15 13.5 19.5)" fill="#2B2623"/><ellipse cx="22.5" cy="19.5" rx="3.2" ry="2.6" transform="rotate(15 22.5 19.5)" fill="#2B2623"/><circle cx="13.8" cy="19" r="1" fill="#FFF"/><circle cx="22.2" cy="19" r="1" fill="#FFF"/><ellipse cx="18" cy="23.5" rx="2" ry="1.4" fill="#2B2623"/></svg>`,
        frog: `<svg class="w-full h-full overflow-visible" viewBox="0 0 36 36" fill="none"><circle cx="11" cy="12" r="4.5" fill="#9AE6B4" stroke="#2B2623" stroke-width="2.3"/><circle cx="25" cy="12" r="4.5" fill="#9AE6B4" stroke="#2B2623" stroke-width="2.3"/><ellipse cx="18" cy="21" rx="11.5" ry="9" fill="#9AE6B4" stroke="#2B2623" stroke-width="2.4"/><circle cx="11" cy="12" r="1.8" fill="#2B2623"/><circle cx="25" cy="12" r="1.8" fill="#2B2623"/><circle cx="11.5" cy="22" r="2" fill="#FF9E9E"/><circle cx="24.5" cy="22" r="2" fill="#FF9E9E"/><path d="M13.5 22.5Q18 26 22.5 22.5" stroke="#2B2623" stroke-width="2.2" stroke-linecap="round"/></svg>`,
        cat: `<svg class="w-full h-full overflow-visible" viewBox="0 0 36 36" fill="none"><path d="M7 9L13 14H23L29 9L28 22C28 27 23.5 30 18 30C12.5 30 8 27 8 22L7 9Z" fill="#FFD6A5" stroke="#2B2623" stroke-width="2.4" stroke-linejoin="round"/><circle cx="13.5" cy="20" r="1.7" fill="#2B2623"/><circle cx="22.5" cy="20" r="1.7" fill="#2B2623"/><polygon points="18,23.5 16,21.5 20,21.5" fill="#FF8B8B"/><path d="M6 21H11M6 24H11M25 21H30M25 24H30" stroke="#2B2623" stroke-width="1.8" stroke-linecap="round"/></svg>`,
        bunny: `<svg class="w-full h-full overflow-visible" viewBox="0 0 36 36" fill="none"><rect x="10.5" y="4" width="5" height="13" rx="2.5" fill="#FFFDF9" stroke="#2B2623" stroke-width="2.2"/><rect x="20.5" y="4" width="5" height="13" rx="2.5" fill="#FFFDF9" stroke="#2B2623" stroke-width="2.2"/><circle cx="18" cy="22" r="9.5" fill="#FFFDF9" stroke="#2B2623" stroke-width="2.4"/><circle cx="14" cy="21" r="1.6" fill="#2B2623"/><circle cx="22" cy="21" r="1.6" fill="#2B2623"/><ellipse cx="18" cy="23.5" rx="1.8" ry="1.3" fill="#FF8B8B"/></svg>`,
        lion: `<svg class="w-full h-full overflow-visible" viewBox="0 0 36 36" fill="none"><circle cx="18" cy="19" r="12.5" fill="#F6AD55" stroke="#2B2623" stroke-width="2.4" stroke-dasharray="4 2"/><circle cx="18" cy="19" r="8.8" fill="#FFE46B" stroke="#2B2623" stroke-width="2.2"/><circle cx="14.5" cy="18" r="1.6" fill="#2B2623"/><circle cx="21.5" cy="18" r="1.6" fill="#2B2623"/><ellipse cx="18" cy="21" rx="2" ry="1.4" fill="#2B2623"/></svg>`,
        koala: `<svg class="w-full h-full overflow-visible" viewBox="0 0 36 36" fill="none"><circle cx="7.5" cy="15" r="5" fill="#CBD5E1" stroke="#2B2623" stroke-width="2.2"/><circle cx="28.5" cy="15" r="5" fill="#CBD5E1" stroke="#2B2623" stroke-width="2.2"/><circle cx="18" cy="20" r="10" fill="#E2E8F0" stroke="#2B2623" stroke-width="2.4"/><ellipse cx="18" cy="21" rx="3" ry="4" fill="#2B2623"/><circle cx="13" cy="18.5" r="1.5" fill="#2B2623"/><circle cx="23" cy="18.5" r="1.5" fill="#2B2623"/></svg>`,
        octopus: `<svg class="w-full h-full overflow-visible" viewBox="0 0 36 36" fill="none"><path d="M8 20C8 13.5 12.5 9 18 9C23.5 9 28 13.5 28 20V26C28 28 26 29 24.5 27.5C23 26 22 28.5 20 28.5C18 28.5 18 26 16 28.5C14 28.5 13 26 11.5 27.5C10 29 8 28 8 26V20Z" fill="#FBB6CE" stroke="#2B2623" stroke-width="2.3" stroke-linejoin="round"/><circle cx="14" cy="18.5" r="1.7" fill="#2B2623"/><circle cx="22" cy="18.5" r="1.7" fill="#2B2623"/><path d="M15.5 22Q18 24 20.5 22" stroke="#2B2623" stroke-width="2" stroke-linecap="round"/></svg>`,
        waiting: `<svg class="w-full h-full overflow-visible" viewBox="0 0 36 36" fill="none"><circle cx="18" cy="18" r="11" fill="#FFFDF9" stroke="#2B2623" stroke-width="2.3" stroke-dasharray="3 3"/><path d="M18 12V18L22 20" stroke="#2B2623" stroke-width="2.3" stroke-linecap="round"/></svg>`
      };

      const EMOJI_TO_AVATAR_KEY = {
        '🦊': 'fox',
        '🐼': 'panda',
        '🐸': 'frog',
        '🐱': 'cat',
        '🐰': 'bunny',
        '🦁': 'lion',
        '🐨': 'koala',
        '🐙': 'octopus',
        '⏳': 'waiting'
      };

      function getAvatarSvgHtml(avatarKeyOrEmoji) {
        const key = EMOJI_TO_AVATAR_KEY[avatarKeyOrEmoji] || avatarKeyOrEmoji || 'fox';
        return DOODLE_AVATAR_SVGS[key] || DOODLE_AVATAR_SVGS.fox;
      }

      function copyToClipboard(text) {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try {
          document.execCommand('copy');
          showToast(`Room code ${text} copied!`, '📋', '#A8E6CF');
        } catch (err) {
          showToast('Tap and hold the code to copy', '📝');
        }
        document.body.removeChild(ta);
      }

      function scrollToBottom(smooth = true) {
        requestAnimationFrame(() => {
          chatStream.scrollTo({
            top: chatStream.scrollHeight + 200,
            behavior: smooth ? 'smooth' : 'auto'
          });
        });
      }

      // Generate strictly 10-character uppercase alphanumeric room code
      function generate10CharCode() {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        const rand = new Uint8Array(10);
        crypto.getRandomValues(rand);
        let code = '';
        for (let i = 0; i < 10; i++) {
          code += chars[rand[i] % chars.length];
        }
        return code;
      }

      function getHostPeerId(roomCode) {
        return `tod-notebook-10c-${roomCode.toLowerCase()}`;
      }

      /* ----------------------------------------------------------
         5. REAL-TIME NETWORKING, RECONNECTION & VOICE (PeerJS)
         - Strictly 2 persons per room
         - Auto-reconnects on browser minimize or temporary network drop
         - Chunked encrypted transfer for photos & messages
      ---------------------------------------------------------- */
      let peer = null;
      let dataConn = null;
      let mediaCall = null;
      let localAudioStream = null;
      let reconnectTimer = null;
      let heartbeatTimer = null;
      let lastPongTime = Date.now();
      let isIntentionalLeave = false;
      const incomingChunks = {};

      function startNetworkSession() {
        isIntentionalLeave = false;
        state.partnerExplicitlyLeft = false;

        if (peer && !peer.destroyed) {
          try { peer.destroy(); } catch (e) {}
        }

        const desiredPeerId = state.role === 'host' ? getHostPeerId(state.roomCode) : undefined;

        peer = new Peer(desiredPeerId, {
          debug: 0,
          config: {
            iceServers: [
              { urls: 'stun:stun.l.google.com:19302' },
              { urls: 'stun:stun1.l.google.com:19302' },
              { urls: 'stun:stun2.l.google.com:19302' }
            ]
          }
        });

        peer.on('open', () => {
          updatePresenceUI();
          if (state.role === 'guest') {
            connectToHost();
          }
        });

        peer.on('connection', (incomingConn) => {
          // Only Host accepts incoming connections
          if (state.role !== 'host') {
            incomingConn.close();
            return;
          }

          const incomingToken = incomingConn.metadata && incomingConn.metadata.playerToken;

          // Enforce 2-Person Room Limit:
          // Allow connection if no partner yet, OR if it is the SAME partner reconnecting after browser minimize!
          const isSamePartnerReconnecting = state.partnerToken && incomingToken === state.partnerToken;
          const isRoomAlreadyOccupiedByAnother =
            state.partnerToken &&
            incomingToken !== state.partnerToken &&
            !state.partnerExplicitlyLeft &&
            dataConn &&
            dataConn.open;

          if (isRoomAlreadyOccupiedByAnother) {
            incomingConn.on('open', () => {
              incomingConn.send({ sys: 'room_full' });
              setTimeout(() => incomingConn.close(), 250);
            });
            return;
          }

          // Accept this partner (new join or seamless reconnect)
          setupDataConnection(incomingConn, isSamePartnerReconnecting);
        });

        // Incoming Live Voice Call
        peer.on('call', (incomingCall) => {
          // Only accept call from our active partner
          if (dataConn && incomingCall.peer !== dataConn.peer) {
            incomingCall.close();
            return;
          }
          mediaCall = incomingCall;
          incomingCall.answer(localAudioStream || undefined);
          bindMediaCallEvents(incomingCall);
        });

        peer.on('disconnected', () => {
          if (isIntentionalLeave) return;
          updateConnectionBanner('Signal paused — reconnecting automatically...', true);
          try {
            peer.reconnect();
          } catch (e) {
            scheduleReconnect();
          }
        });

        peer.on('error', (err) => {
          if (isIntentionalLeave) return;

          if (err.type === 'unavailable-id' && state.role === 'host') {
            // Host ID briefly still held after a quick reload; retry in 1.5s
            setTimeout(() => {
              if (!isIntentionalLeave) startNetworkSession();
            }, 1500);
            return;
          }

          if (err.type === 'peer-unavailable' && state.role === 'guest') {
            updateConnectionBanner('Looking for your friend’s notebook... retrying...', true);
            scheduleReconnect();
            return;
          }

          scheduleReconnect();
        });
      }

      function connectToHost() {
        if (!peer || peer.disconnected || peer.destroyed || isIntentionalLeave) return;
        if (dataConn && dataConn.open) return;

        const hostId = getHostPeerId(state.roomCode);
        const conn = peer.connect(hostId, {
          reliable: true,
          metadata: {
            playerToken: state.playerToken
          }
        });
        setupDataConnection(conn, Boolean(state.partnerToken));
      }

      function setupDataConnection(conn, isReconnection = false) {
        if (dataConn && dataConn !== conn) {
          try { dataConn.close(); } catch (e) {}
        }
        dataConn = conn;

        conn.on('open', async () => {
          lastPongTime = Date.now();
          startHeartbeat();

          // Perform ECDH key exchange handshake
          const myPubJwk = await CryptoEngine.generateEcdhPublicJwk();
          conn.send({
            sys: 'handshake',
            pubJwk: myPubJwk,
            playerToken: state.playerToken,
            isReconnection
          });
        });

        conn.on('data', async (rawPacket) => {
          lastPongTime = Date.now();
          if (!rawPacket || typeof rawPacket !== 'object') return;

          // 1. Handle Room Full signal
          if (rawPacket.sys === 'room_full') {
            showToast('This 2-player notebook is already full!', '🔒', '#FF8B8B');
            exitToLobby(false);
            return;
          }

          // 2. Handle Heartbeat Ping/Pong
          if (rawPacket.sys === 'ping') {
            if (dataConn && dataConn.open) dataConn.send({ sys: 'pong' });
            return;
          }
          if (rawPacket.sys === 'pong') {
            return;
          }

          // 3. Handle Handshake & Key Exchange
          if (rawPacket.sys === 'handshake') {
            const wasAlreadyKnown = state.partnerToken === rawPacket.playerToken;
            state.partnerToken = rawPacket.playerToken;
            state.partnerOnline = true;
            state.partnerExplicitlyLeft = false;

            if (rawPacket.pubJwk) {
              await CryptoEngine.completeEcdhHandshake(rawPacket.pubJwk, state.roomCode);
            }

            // Send encrypted profile + state sync
            await sendEncrypted({
              type: 'profile_sync',
              name: state.myName,
              avatar: state.myAvatar,
              micOn: state.myMicOn,
              isReconnection: wasAlreadyKnown || rawPacket.isReconnection,
              scores: state.scores,
              turn: state.turn,
              gamePhase: state.gamePhase,
              activeCard: state.activeCard,
              customDeck: state.customDeck
            });

            // If my mic was on before a blip, re-establish voice call
            if (state.myMicOn && localAudioStream) {
              initiateVoiceCall();
            }
            return;
          }

          // 4. Handle Chunked Encrypted Payloads (Used for Photos & Data)
          if (rawPacket.sys === 'chunk') {
            const { id, idx, total, piece } = rawPacket;
            if (!incomingChunks[id]) {
              incomingChunks[id] = { parts: new Array(total), received: 0 };
            }
            if (incomingChunks[id].parts[idx] === undefined) {
              incomingChunks[id].parts[idx] = piece;
              incomingChunks[id].received++;
            }
            if (incomingChunks[id].received === total) {
              const fullString = incomingChunks[id].parts.join('');
              delete incomingChunks[id];
              try {
                const encryptedEnvelope = JSON.parse(fullString);
                const decrypted = await CryptoEngine.decryptPayload(encryptedEnvelope);
                if (decrypted) handleDecryptedAction(decrypted);
              } catch (e) {
                console.warn('Failed to reassemble chunked packet:', e);
              }
            }
            return;
          }

          // 5. Handle Standard Encrypted Envelope
          if (rawPacket.iv && rawPacket.ct) {
            try {
              const decrypted = await CryptoEngine.decryptPayload(rawPacket);
              if (decrypted) handleDecryptedAction(decrypted);
            } catch (e) {
              console.warn('Could not decode packet:', e);
            }
          }
        });

        conn.on('close', () => {
          if (isIntentionalLeave) return;
          state.partnerOnline = false;
          state.partnerTyping = false;
          updatePresenceUI();

          if (!state.partnerExplicitlyLeft) {
            updateConnectionBanner(`${state.partnerName} connection paused — holding room open...`, true);
            scheduleReconnect();
          }
        });

        conn.on('error', () => {
          if (!isIntentionalLeave && !state.partnerExplicitlyLeft) {
            scheduleReconnect();
          }
        });
      }

      async function sendEncrypted(payloadObj) {
        if (!dataConn || !dataConn.open) return false;
        try {
          const encrypted = await CryptoEngine.encryptPayload(payloadObj);
          if (!encrypted) return false;

          const serialized = JSON.stringify(encrypted);
          // If payload is large (e.g. a shared photo), split into 24KB chunks for WebRTC stability
          const CHUNK_SIZE = 24000;
          if (serialized.length > CHUNK_SIZE) {
            const msgId = 'm_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
            const total = Math.ceil(serialized.length / CHUNK_SIZE);
            for (let i = 0; i < total; i++) {
              const piece = serialized.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
              dataConn.send({ sys: 'chunk', id: msgId, idx: i, total, piece });
            }
          } else {
            dataConn.send(encrypted);
          }
          return true;
        } catch (err) {
          console.warn('Send error:', err);
          return false;
        }
      }

      function startHeartbeat() {
        clearInterval(heartbeatTimer);
        heartbeatTimer = setInterval(() => {
          if (isIntentionalLeave) return;
          if (dataConn && dataConn.open) {
            dataConn.send({ sys: 'ping' });
            // If no data/pong for 14 seconds, connection silently stalled
            if (Date.now() - lastPongTime > 14000) {
              state.partnerOnline = false;
              updatePresenceUI();
              scheduleReconnect();
            }
          } else if (!state.partnerExplicitlyLeft) {
            scheduleReconnect();
          }
        }, 3500);
      }

      function scheduleReconnect() {
        if (isIntentionalLeave || state.partnerExplicitlyLeft) return;
        clearTimeout(reconnectTimer);
        reconnectTimer = setTimeout(() => {
          if (isIntentionalLeave) return;
          if (!peer || peer.destroyed) {
            startNetworkSession();
          } else if (peer.disconnected) {
            try { peer.reconnect(); } catch (e) { startNetworkSession(); }
          } else if (state.role === 'guest' && (!dataConn || !dataConn.open)) {
            connectToHost();
          }
        }, 2000);
      }

      // Immediately recover when user switches back from another app or un-minimizes mobile browser
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible' && state.roomCode && !isIntentionalLeave) {
          syncVisualViewport();
          lastPongTime = Date.now();
          if (!peer || peer.destroyed) {
            startNetworkSession();
          } else if (peer.disconnected) {
            try { peer.reconnect(); } catch (e) { startNetworkSession(); }
          } else if (state.role === 'guest' && (!dataConn || !dataConn.open)) {
            connectToHost();
          } else if (dataConn && dataConn.open) {
            dataConn.send({ sys: 'ping' });
          }
        }
      });

      window.addEventListener('online', () => {
        if (state.roomCode && !isIntentionalLeave) {
          showToast('Back online! Syncing notebook...', '📶', '#A8E6CF');
          scheduleReconnect();
        }
      });

      /* ----------------------------------------------------------
         6. LIVE VOICE FEATURE (Mic On / Off with Real-Time Status)
      ---------------------------------------------------------- */
      async function toggleMyMicrophone() {
        if (!state.myMicOn) {
          // Turn Mic ON
          try {
            if (!localAudioStream) {
              localAudioStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                  echoCancellation: true,
                  noiseSuppression: true,
                  autoGainControl: true
                },
                video: false
              });
            }
            localAudioStream.getAudioTracks().forEach(track => {
              track.enabled = true;
            });
            state.myMicOn = true;
            updateMicUI();
            showToast('Microphone is LIVE 🎙️', '🎙️', '#A8E6CF');

            // Notify partner & start WebRTC media call
            sendEncrypted({ type: 'mic_status', micOn: true });
            initiateVoiceCall();
          } catch (err) {
            state.myMicOn = false;
            updateMicUI();
            showToast('Please allow microphone access to use live voice', '🎙️', '#FF8B8B');
          }
        } else {
          // Turn Mic OFF
          state.myMicOn = false;
          if (localAudioStream) {
            localAudioStream.getAudioTracks().forEach(track => {
              track.enabled = false;
            });
          }
          updateMicUI();
          showToast('Microphone muted 🔇', '🔇', '#FFE46B');
          sendEncrypted({ type: 'mic_status', micOn: false });
        }
      }

      function initiateVoiceCall() {
        if (!peer || !dataConn || !dataConn.open || !localAudioStream) return;
        try {
          if (mediaCall) {
            try { mediaCall.close(); } catch (e) {}
          }
          mediaCall = peer.call(dataConn.peer, localAudioStream);
          bindMediaCallEvents(mediaCall);
        } catch (e) {
          console.warn('Voice call initiation warning:', e);
        }
      }

      function bindMediaCallEvents(callObj) {
        if (!callObj) return;
        callObj.on('stream', (remoteStream) => {
          if (el.remoteAudio.srcObject !== remoteStream) {
            el.remoteAudio.srcObject = remoteStream;
            el.remoteAudio.play().catch(() => {});
          }
        });
      }

      function stopAllMedia() {
        if (localAudioStream) {
          localAudioStream.getTracks().forEach(t => t.stop());
          localAudioStream = null;
        }
        if (mediaCall) {
          try { mediaCall.close(); } catch (e) {}
          mediaCall = null;
        }
        state.myMicOn = false;
        updateMicUI();
      }

      function updateMicUI() {
        // My Mic Button
        if (state.myMicOn) {
          el.micToggleBtn.className = 'sketch-btn w-9 h-9 flex items-center justify-center bg-[#A8E6CF] text-base relative mic-live-pulse';
          el.myMicSlash.classList.add('hidden');
        } else {
          el.micToggleBtn.className = 'sketch-btn w-9 h-9 flex items-center justify-center bg-white text-base relative';
          el.myMicSlash.classList.remove('hidden');
        }

        // Partner Mic Badge in Header
        if (state.partnerOnline) {
          el.partnerMicBadge.classList.remove('hidden');
          el.partnerMicBadge.classList.add('inline-flex');
          if (state.partnerMicOn) {
            el.partnerMicBadge.className = 'inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[11px] font-ui font-semibold rounded-full border border-[#2B2623] bg-[#A8E6CF] shrink-0 mic-live-pulse';
            el.partnerMicIcon.textContent = '🎙️ Live';
          } else {
            el.partnerMicBadge.className = 'inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[11px] font-ui font-medium rounded-full border border-[#2B2623] bg-gray-100 shrink-0';
            el.partnerMicIcon.textContent = '🔇 Off';
          }
        } else {
          el.partnerMicBadge.classList.add('hidden');
        }
      }

      /* ----------------------------------------------------------
         7. HANDLING INCOMING ACTIONS (Chat, Typing, Join/Leave, Game, Photos)
      ---------------------------------------------------------- */
      let partnerTypingTimeout = null;

      function handleDecryptedAction(data) {
        switch (data.type) {
          case 'profile_sync': {
            const previousName = state.partnerName;
            const isFirstJoin = previousName === 'Waiting for friend...' || previousName === 'Connecting to host...';
            state.partnerName = data.name || 'Friend';
            state.partnerAvatar = data.avatar || 'panda';
            state.partnerMicOn = Boolean(data.micOn);
            state.partnerOnline = true;
            state.partnerExplicitlyLeft = false;

            // Merge custom deck prompts
            if (Array.isArray(data.customDeck)) {
              const existingIds = new Set(state.customDeck.map(d => d.id));
              data.customDeck.forEach(item => {
                if (item && item.id && !existingIds.has(item.id)) {
                  state.customDeck.push(item);
                }
              });
            }

            // Host is authoritative for score/card state if already playing
            if (state.role === 'guest' && data.scores) {
              state.scores = {
                me: data.scores.partner || 0,
                partner: data.scores.me || 0
              };
              state.turn = data.turn === 'me' ? 'partner' : 'me';
              if (data.activeCard) {
                state.activeCard = {
                  ...data.activeCard,
                  target: data.activeCard.target === 'me' ? 'partner' : 'me'
                };
                state.gamePhase = 'card';
              }
            }

            updatePresenceUI();
            updateMicUI();
            renderGameStage();
            saveSessionState();

            if (isFirstJoin || !data.isReconnection) {
              appendSystemEvent(`✨ ${state.partnerName} joined the notebook!`, 'join');
              showToast(`${state.partnerName} joined the room!`, '🎉', '#A8E6CF');
            } else {
              showToast(`${state.partnerName} is back online!`, '✨', '#A8E6CF');
            }
            break;
          }

          case 'typing': {
            state.partnerTyping = Boolean(data.isTyping);
            clearTimeout(partnerTypingTimeout);
            if (state.partnerTyping) {
              partnerTypingTimeout = setTimeout(() => {
                state.partnerTyping = false;
                updateTypingUI();
              }, 3500);
            }
            updateTypingUI();
            break;
          }

          case 'mic_status': {
            state.partnerMicOn = Boolean(data.micOn);
            updateMicUI();
            showToast(
              state.partnerMicOn
                ? `${state.partnerName} turned Mic ON 🎙️`
                : `${state.partnerName} muted their Mic 🔇`,
              state.partnerMicOn ? '🎙️' : '🔇',
              state.partnerMicOn ? '#A8E6CF' : '#FFE46B'
            );
            break;
          }

          case 'chat_msg': {
            state.partnerTyping = false;
            updateTypingUI();
            appendChatMessage({
              sender: 'partner',
              name: state.partnerName,
              avatar: state.partnerAvatar,
              text: data.text,
              time: data.time || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            });
            break;
          }

          case 'photo_msg': {
            state.partnerTyping = false;
            updateTypingUI();
            appendPhotoMessage({
              sender: 'partner',
              name: state.partnerName,
              avatar: state.partnerAvatar,
              dataUrl: data.dataUrl,
              caption: data.caption || `Snap from ${state.partnerName}`,
              time: data.time || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            });
            showToast(`${state.partnerName} shared a photo! 📷`, '📷', '#FFE46B');
            break;
          }

          case 'game_choice': {
            // Partner chose Truth or Dare and wants us to write/pick a prompt for them, or vice versa
            state.selectedType = data.choice;
            appendSystemEvent(
              `🎲 ${state.partnerName} picked ${data.choice.toUpperCase()}! Write a custom ${data.choice} for them above!`,
              'game'
            );
            state.turn = 'partner';
            state.gamePhase = 'compose';
            // Make sure stage is visible so user sees they need to write a prompt
            gameStageSection.classList.remove('hidden');
            renderGameStage();
            showToast(`${state.partnerName} picked ${data.choice.toUpperCase()}! Write their prompt!`, '🎴', '#FFE46B');
            break;
          }

          case 'game_card_sent': {
            state.activeCard = {
              type: data.cardType,
              text: data.text,
              target: data.target === 'me' ? 'partner' : 'me',
              authorName: data.authorName
            };
            state.gamePhase = 'card';
            gameStageSection.classList.remove('hidden');
            renderGameStage();
            appendCardToChatStream(state.activeCard);
            saveSessionState();
            break;
          }

          case 'game_card_complete': {
            if (data.completedBy === 'me') {
              state.scores.partner += 1;
            } else {
              state.scores.me += 1;
            }
            state.turn = state.turn === 'me' ? 'partner' : 'me';
            state.activeCard = null;
            state.gamePhase = 'pick';
            renderGameStage();
            appendSystemEvent(`⭐ ${data.playerName} completed the ${data.cardType.toUpperCase()}! (+1 Star)`, 'complete');
            saveSessionState();
            break;
          }

          case 'game_card_skip': {
            state.turn = state.turn === 'me' ? 'partner' : 'me';
            state.activeCard = null;
            state.gamePhase = 'pick';
            renderGameStage();
            appendSystemEvent(`🔄 ${data.playerName} skipped the card. Next turn!`, 'game');
            saveSessionState();
            break;
          }

          case 'spin_turn': {
            state.turn = data.nextTurn === 'me' ? 'partner' : 'me';
            state.gamePhase = 'pick';
            renderGameStage();
            const who = state.turn === 'me' ? `Your (${state.myName})` : `${state.partnerName}'s`;
            appendSystemEvent(`✏️ Pencil spun! It landed on ${who} turn!`, 'game');
            showToast(`Pencil landed on ${who} turn!`, '✏️', '#FFE46B');
            break;
          }

          case 'deck_add': {
            if (data.item && !state.customDeck.some(d => d.id === data.item.id)) {
              state.customDeck.unshift(data.item);
              renderDeckList();
              showToast(`${state.partnerName} added a new custom ${data.item.type}!`, '📒', '#D5C6FF');
              saveSessionState();
            }
            break;
          }

          case 'explicit_leave': {
            state.partnerOnline = false;
            state.partnerTyping = false;
            state.partnerMicOn = false;
            state.partnerExplicitlyLeft = true;
            updatePresenceUI();
            updateMicUI();
            updateTypingUI();
            appendSystemEvent(`🚪 ${state.partnerName} left the notebook.`, 'leave');
            updateConnectionBanner(`${state.partnerName} left the room. A new friend can join with the code.`, false);
            showToast(`${state.partnerName} left the room`, '👋', '#FF8B8B');
            break;
          }
        }
      }

      /* ----------------------------------------------------------
         8. UI RENDERING: PRESENCE, TYPING, GAME STAGE & CHAT
      ---------------------------------------------------------- */
      function updatePresenceUI() {
        el.headerRoomCode.textContent = state.roomCode || '----------';
        el.partnerAvatarBox.innerHTML = `<div class="w-7 h-7">${getAvatarSvgHtml(state.partnerAvatar)}</div>`;
        el.partnerNameDisplay.textContent = state.partnerName;

        if (state.partnerOnline) {
          el.partnerOnlineDot.className = 'absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-[#4ADE80] border-2 border-[#2B2623]';
          el.partnerStatusText.textContent = 'Online right now';
          el.partnerStatusText.className = 'text-emerald-700 font-ui font-medium truncate';
          el.connectionBanner.classList.add('hidden');
        } else if (state.partnerExplicitlyLeft) {
          el.partnerOnlineDot.className = 'absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-[#FF6B6B] border-2 border-[#2B2623]';
          el.partnerStatusText.textContent = 'Left the room';
          el.partnerStatusText.className = 'text-rose-600 font-ui font-medium truncate';
          el.connectionBanner.classList.remove('hidden');
        } else {
          el.partnerOnlineDot.className = 'absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-amber-400 border-2 border-[#2B2623]';
          el.partnerStatusText.textContent = state.partnerToken ? 'Reconnecting...' : 'Waiting to join...';
          el.partnerStatusText.className = 'text-[#6E655F] truncate';
          el.connectionBanner.classList.remove('hidden');
          updateConnectionBanner(
            state.partnerToken
              ? `Holding room for ${state.partnerName}...`
              : `Room Code: ${state.roomCode} — Waiting for friend...`,
            true
          );
        }
      }

      function updateConnectionBanner(message, showSpinner = true) {
        el.connectionBanner.classList.remove('hidden');
        el.bannerText.textContent = message;
        if (showSpinner) {
          el.bannerSpinner.classList.remove('hidden');
        } else {
          el.bannerSpinner.classList.add('hidden');
        }
      }

      function updateTypingUI() {
        if (state.partnerTyping && state.partnerOnline) {
          el.headerTypingBadge.classList.remove('hidden');
          el.headerTypingBadge.classList.add('inline-flex');
          el.partnerStatusText.classList.add('hidden');
          el.chatTypingRow.classList.remove('hidden');
          el.chatTypingLabel.textContent = `${state.partnerName} is scribbling...`;
        } else {
          el.headerTypingBadge.classList.add('hidden');
          el.headerTypingBadge.classList.remove('inline-flex');
          el.partnerStatusText.classList.remove('hidden');
          el.chatTypingRow.classList.add('hidden');
        }
      }

      function renderGameStage() {
        // Scoreboard
        el.scoreDisplay.textContent = `⭐ You ${state.scores.me} — ${state.scores.partner} ${state.partnerOnline ? state.partnerName : 'Friend'}`;

        // Turn Indicator
        if (state.turn === 'me') {
          el.turnIndicatorPill.textContent = `🎯 Your Turn (${state.myName})`;
          el.turnIndicatorPill.className = 'px-2.5 py-0.5 bg-[#7EE0C6] border-2 border-[#2B2623] rounded-full font-semibold text-[#2B2623]';
        } else {
          const pName = state.partnerOnline ? state.partnerName : 'Friend';
          el.turnIndicatorPill.textContent = `🎲 ${pName}'s Turn`;
          el.turnIndicatorPill.className = 'px-2.5 py-0.5 bg-[#FFE46B] border-2 border-[#2B2623] rounded-full font-semibold text-[#2B2623]';
        }

        el.stagePickMode.classList.add('hidden');
        el.stageComposePrompt.classList.add('hidden');
        el.stageActiveCard.classList.add('hidden');

        if (state.gamePhase === 'pick') {
          el.stagePickMode.classList.remove('hidden');
          el.stagePickTitle.textContent =
            state.turn === 'me'
              ? 'Your Turn! Pick Truth or Dare:'
              : `Pick Truth or Dare or Challenge ${state.partnerOnline ? state.partnerName : 'Friend'}:`;
        } else if (state.gamePhase === 'compose') {
          el.stageComposePrompt.classList.remove('hidden');
          const isTruth = state.selectedType === 'truth';
          const targetLabel = state.partnerOnline ? state.partnerName : 'Friend';
          el.composeBadge.textContent = isTruth
            ? `💬 Write a Custom Truth for ${targetLabel}`
            : `⚡ Write a Custom Dare for ${targetLabel}`;
          el.composeBadge.style.backgroundColor = isTruth ? '#7EE0C6' : '#FF8B8B';
          el.customPromptInput.placeholder = isTruth
            ? `Ask ${targetLabel} a fun custom truth question...`
            : `Give ${targetLabel} a playful custom dare...`;
        } else if (state.gamePhase === 'card' && state.activeCard) {
          el.stageActiveCard.classList.remove('hidden');
          const isTruth = state.activeCard.type === 'truth';
          el.activeCardBadge.textContent = isTruth ? '💬 TRUTH CARD' : '⚡ DARE CARD';
          el.activeCardBadge.style.backgroundColor = isTruth ? '#7EE0C6' : '#FF8B8B';
          const targetWho = state.activeCard.target === 'me' ? `For You (${state.myName})` : `For ${state.partnerName}`;
          el.activeCardTarget.textContent = `${targetWho} • by ${state.activeCard.authorName}`;
          el.activeCardText.textContent = state.activeCard.text;
        }
      }

      /* ----------------------------------------------------------
         9. CHAT STREAM, SYSTEM BANNERS & PHOTO POLAROIDS
      ---------------------------------------------------------- */
      function appendSystemEvent(text, kind = 'info') {
        const colors = {
          join: 'bg-[#D1FAE5] border-[#2B2623]',
          leave: 'bg-[#FFE3E3] border-[#2B2623]',
          complete: 'bg-[#FEF3C7] border-[#2B2623]',
          game: 'bg-[#EDE9FE] border-[#2B2623]',
          info: 'bg-white border-[#2B2623]'
        };
        const wrapper = document.createElement('div');
        wrapper.className = 'flex justify-center my-1.5 animate-pop';
        wrapper.innerHTML = `
          <div class="px-3 py-1 rounded-full border-2 ${colors[kind] || colors.info} text-xs font-ui font-medium text-[#2B2623] shadow-sm text-center max-w-[92%]">
            ${escapeHtml(text)}
          </div>
        `;
        chatStream.appendChild(wrapper);
        scrollToBottom();
      }

      function appendCardToChatStream(card) {
        const isTruth = card.type === 'truth';
        const bg = isTruth ? 'bg-[#E6FBF5]' : 'bg-[#FFF0F0]';
        const pillBg = isTruth ? 'bg-[#7EE0C6]' : 'bg-[#FF8B8B]';
        const targetLabel = card.target === 'me' ? state.myName : state.partnerName;

        const wrapper = document.createElement('div');
        wrapper.className = 'my-2 animate-pop';
        wrapper.innerHTML = `
          <div class="sketch-box ${bg} p-3 mx-auto max-w-[92%]">
            <div class="flex items-center justify-between text-xs font-ui mb-1">
              <span class="px-2 py-0.5 ${pillBg} border border-[#2B2623] rounded-full font-bold uppercase">
                ${isTruth ? '💬 Custom Truth' : '⚡ Custom Dare'}
              </span>
              <span class="text-[#6E655F]">For ${escapeHtml(targetLabel)}</span>
            </div>
            <p class="font-title text-2xl font-bold text-[#2B2623] leading-snug">${escapeHtml(card.text)}</p>
          </div>
        `;
        chatStream.appendChild(wrapper);
        scrollToBottom();
      }

      function appendChatMessage(msg, save = true) {
        const isMe = msg.sender === 'me';
        const wrapper = document.createElement('div');
        wrapper.className = `flex items-end gap-2 ${isMe ? 'flex-row-reverse' : 'flex-row'} animate-pop`;

        const bubbleBg = isMe ? 'bg-[#FFF9DB]' : 'bg-white';
        wrapper.innerHTML = `
          <div class="w-8 h-8 p-1 sketch-pill bg-white flex items-center justify-center shrink-0 select-none">
            ${getAvatarSvgHtml(msg.avatar)}
          </div>
          <div class="max-w-[76%] ${bubbleBg} sketch-box px-3.5 py-2">
            <div class="flex items-center justify-between gap-3 text-[11px] font-ui text-[#6E655F] mb-0.5">
              <span class="font-semibold text-[#2B2623]">${escapeHtml(isMe ? 'You' : msg.name)}</span>
              <span>${escapeHtml(msg.time)}</span>
            </div>
            <p class="text-base font-hand text-[#2B2623] leading-snug break-words">${escapeHtml(msg.text)}</p>
          </div>
        `;
        chatStream.appendChild(wrapper);
        scrollToBottom();

        if (save) {
          state.chatHistory.push({ kind: 'text', ...msg });
          saveSessionState();
        }
      }

      function appendPhotoMessage(msg, save = true) {
        const isMe = msg.sender === 'me';
        const wrapper = document.createElement('div');
        wrapper.className = `flex items-end gap-2 ${isMe ? 'flex-row-reverse' : 'flex-row'} animate-pop`;

        wrapper.innerHTML = `
          <div class="w-8 h-8 p-1 sketch-pill bg-white flex items-center justify-center shrink-0 select-none">
            ${getAvatarSvgHtml(msg.avatar)}
          </div>
          <div class="polaroid-frame max-w-[230px] cursor-pointer group">
            <div class="flex items-center justify-between text-[11px] font-ui text-[#6E655F] mb-1">
              <span class="font-semibold text-[#2B2623]">📷 ${escapeHtml(isMe ? 'Your Snap' : msg.name)}</span>
              <span>${escapeHtml(msg.time)}</span>
            </div>
            <img src="${msg.dataUrl}" alt="Shared photo" class="w-full max-h-48 object-cover rounded border border-[#2B2623]" />
            <p class="font-title text-xl text-center text-[#2B2623] mt-1 leading-none">${escapeHtml(msg.caption || 'Tap to view full size')}</p>
          </div>
        `;

        const polaroid = wrapper.querySelector('.polaroid-frame');
        polaroid.addEventListener('click', () => {
          el.lightboxImg.src = msg.dataUrl;
          el.lightboxCaption.textContent = `${isMe ? 'Shared by You' : 'Shared by ' + msg.name} • ${msg.time}`;
          el.photoLightboxModal.classList.remove('hidden');
        });

        chatStream.appendChild(wrapper);
        scrollToBottom();

        if (save) {
          state.chatHistory.push({ kind: 'photo', ...msg });
          saveSessionState();
        }
      }

      /* ----------------------------------------------------------
         10. IMAGE COMPRESSION & ENCRYPTED PHOTO SHARING
      ---------------------------------------------------------- */
      function compressAndSendImage(file) {
        if (!file || !file.type.startsWith('image/')) {
          showToast('Please select a valid photo file', '📷', '#FF8B8B');
          return;
        }

        showToast('Preparing & sending your snap...', '📷', '#FFE46B');

        const reader = new FileReader();
        reader.onload = (e) => {
          const img = new Image();
          img.onload = async () => {
            const MAX_DIM = 850;
            let width = img.width;
            let height = img.height;
            if (width > height && width > MAX_DIM) {
              height = Math.round((height * MAX_DIM) / width);
              width = MAX_DIM;
            } else if (height > MAX_DIM) {
              width = Math.round((width * MAX_DIM) / height);
              height = MAX_DIM;
            }

            const canvas = document.createElement('canvas');
            canvas.width = width;
            canvas.height = height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, width, height);

            const compressedDataUrl = canvas.toDataURL('image/jpeg', 0.78);
            const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            appendPhotoMessage({
              sender: 'me',
              name: state.myName,
              avatar: state.myAvatar,
              dataUrl: compressedDataUrl,
              caption: 'Notebook Snap ✨',
              time: timeStr
            });

            const sent = await sendEncrypted({
              type: 'photo_msg',
              dataUrl: compressedDataUrl,
              caption: `Snap from ${state.myName} ✨`,
              time: timeStr
            });

            if (!sent && !state.partnerOnline) {
              showToast('Photo added to notebook! Friend will see it when connected.', '📷', '#FFE46B');
            }
          };
          img.src = e.target.result;
        };
        reader.readAsDataURL(file);
      }

      /* ----------------------------------------------------------
         11. CUSTOM PROMPT DECK MANAGER
      ---------------------------------------------------------- */
      function renderDeckList() {
        el.deckListContainer.innerHTML = '';
        const filtered = state.customDeck.filter(
          item => state.deckFilter === 'all' || item.type === state.deckFilter
        );

        if (filtered.length === 0) {
          el.deckListContainer.innerHTML = `
            <div class="text-center py-6 text-sm text-[#6E655F]">
              No prompts in this category yet. Write one above!
            </div>
          `;
          return;
        }

        filtered.forEach(item => {
          const isTruth = item.type === 'truth';
          const row = document.createElement('div');
          row.className = 'sketch-box p-2.5 bg-white flex items-center justify-between gap-2';
          row.innerHTML = `
            <div class="min-w-0 flex-1">
              <span class="inline-block px-2 py-0.2 text-[10px] font-ui font-bold uppercase rounded-full border border-[#2B2623] ${isTruth ? 'bg-[#7EE0C6]' : 'bg-[#FF8B8B]'} mr-1">
                ${isTruth ? 'TRUTH' : 'DARE'}
              </span>
              <span class="text-base font-hand text-[#2B2623] break-words">${escapeHtml(item.text)}</span>
            </div>
            <button type="button" class="use-prompt-btn sketch-btn px-2.5 py-1 bg-[#FFE46B] text-xs font-ui font-semibold shrink-0">
              Play 🃏
            </button>
          `;

          row.querySelector('.use-prompt-btn').addEventListener('click', () => {
            el.customDeckModal.classList.add('hidden');
            launchCard(item.type, item.text, 'partner');
          });

          el.deckListContainer.appendChild(row);
        });
      }

      function launchCard(cardType, text, targetWho = 'partner') {
        const cleanText = text.trim();
        if (!cleanText) return;

        state.activeCard = {
          type: cardType,
          text: cleanText,
          target: targetWho,
          authorName: state.myName
        };
        state.gamePhase = 'card';
        renderGameStage();
        appendCardToChatStream(state.activeCard);
        saveSessionState();

        sendEncrypted({
          type: 'game_card_sent',
          cardType,
          text: cleanText,
          target: targetWho,
          authorName: state.myName
        });
      }

      /* ----------------------------------------------------------
         12. EVENT LISTENERS & USER INTERACTIONS
      ---------------------------------------------------------- */
      // Avatar Picker
      el.avatarPicker.addEventListener('click', (e) => {
        const btn = e.target.closest('.avatar-btn');
        if (!btn) return;
        state.myAvatar = btn.dataset.avatar;
        document.querySelectorAll('.avatar-btn').forEach(b => {
          b.classList.remove('bg-[#FFE46B]', 'scale-105');
          b.classList.add('bg-white');
        });
        btn.classList.remove('bg-white');
        btn.classList.add('bg-[#FFE46B]', 'scale-105');
      });

      // Live 10-Character Code Input Formatting
      el.joinCodeInput.addEventListener('input', () => {
        const cleaned = el.joinCodeInput.value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 10);
        el.joinCodeInput.value = cleaned;
        el.codeCharCounter.textContent = `${cleaned.length} / 10`;
        if (cleaned.length === 10) {
          el.codeCharCounter.className = 'text-xs font-ui font-bold text-emerald-700';
        } else {
          el.codeCharCounter.className = 'text-xs font-ui font-semibold text-[#6E655F]';
        }
      });

      function validateNickname() {
        const nameVal = el.playerNameInput.value.trim();
        if (!nameVal) {
          showToast('Please enter your nickname first! ✏️', '⚠️', '#FF8B8B');
          el.playerNameInput.focus();
          el.playerNameInput.classList.remove('animate-shake');
          void el.playerNameInput.offsetWidth; // Force CSS reflow to re-trigger animation
          el.playerNameInput.classList.add('animate-shake');
          el.playerNameInput.style.borderColor = '#EF4444';
          el.playerNameInput.style.backgroundColor = '#FEF2F2';
          return null;
        }
        return nameVal;
      }

      el.playerNameInput.addEventListener('input', () => {
        if (el.playerNameInput.value.trim()) {
          el.playerNameInput.style.borderColor = '';
          el.playerNameInput.style.backgroundColor = '';
        }
      });

      // Create 10-Char Room
      el.createRoomBtn.addEventListener('click', async () => {
        const nameVal = validateNickname();
        if (!nameVal) return;

        state.myName = nameVal;
        state.role = 'host';
        state.roomCode = generate10CharCode();
        state.partnerName = 'Waiting for friend...';
        state.partnerAvatar = 'waiting';
        state.partnerToken = null;
        state.partnerOnline = false;
        state.scores = { me: 0, partner: 0 };
        state.turn = 'me';
        state.gamePhase = 'pick';
        state.chatHistory = [];

        await CryptoEngine.initRoomKey(state.roomCode);
        enterRoomScreen();
        startNetworkSession();
        saveSessionState();
      });

      // Join Room with 10-Char Code
      el.joinRoomBtn.addEventListener('click', async () => {
        const nameVal = validateNickname();
        if (!nameVal) return;

        const code = el.joinCodeInput.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
        if (code.length !== 10) {
          showToast('Please enter a full 10-character room code!', '🔑', '#FF8B8B');
          el.joinCodeInput.focus();
          return;
        }

        state.myName = nameVal;
        state.role = 'guest';
        state.roomCode = code;
        state.partnerName = 'Connecting to host...';
        state.partnerAvatar = 'waiting';
        state.partnerToken = null;
        state.partnerOnline = false;
        state.scores = { me: 0, partner: 0 };
        state.turn = 'partner';
        state.gamePhase = 'pick';
        state.chatHistory = [];

        await CryptoEngine.initRoomKey(state.roomCode);
        enterRoomScreen();
        startNetworkSession();
        saveSessionState();
      });

      el.joinCodeInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          el.joinRoomBtn.click();
        }
      });

      function enterRoomScreen() {
        el.lobbyScreen.classList.add('hidden');
        el.roomScreen.classList.remove('hidden');
        updatePresenceUI();
        updateMicUI();
        renderGameStage();
        syncVisualViewport();
      }

      function exitToLobby(sendLeaveSignal = true) {
        isIntentionalLeave = true;
        clearInterval(heartbeatTimer);
        clearTimeout(reconnectTimer);

        if (sendLeaveSignal && dataConn && dataConn.open) {
          sendEncrypted({ type: 'explicit_leave' });
        }

        stopAllMedia();
        setTimeout(() => {
          if (dataConn) {
            try { dataConn.close(); } catch (e) {}
            dataConn = null;
          }
          if (peer) {
            try { peer.destroy(); } catch (e) {}
            peer = null;
          }
        }, 120);

        state.roomCode = '';
        state.partnerToken = null;
        state.partnerOnline = false;
        clearSessionState();

        el.leaveConfirmModal.classList.add('hidden');
        el.roomScreen.classList.add('hidden');
        el.lobbyScreen.classList.remove('hidden');
      }

      // Header Controls
      el.copyCodePill.addEventListener('click', () => copyToClipboard(state.roomCode));
      el.bannerShareBtn.addEventListener('click', () => copyToClipboard(state.roomCode));
      el.micToggleBtn.addEventListener('click', toggleMyMicrophone);

      el.toggleStageBtn.addEventListener('click', () => {
        const isHidden = gameStageSection.classList.toggle('hidden');
        userManuallyCollapsedStage = isHidden;
        scrollToBottom(false);
      });

      el.leaveRoomBtn.addEventListener('click', () => {
        el.leaveConfirmModal.classList.remove('hidden');
      });
      el.cancelLeaveBtn.addEventListener('click', () => {
        el.leaveConfirmModal.classList.add('hidden');
      });
      el.confirmLeaveBtn.addEventListener('click', () => {
        exitToLobby(true);
      });

      // Game Stage Actions
      el.chooseTruthBtn.addEventListener('click', () => {
        state.selectedType = 'truth';
        state.gamePhase = 'compose';
        renderGameStage();
        el.customPromptInput.focus();
        sendEncrypted({ type: 'game_choice', choice: 'truth' });
      });

      el.chooseDareBtn.addEventListener('click', () => {
        state.selectedType = 'dare';
        state.gamePhase = 'compose';
        renderGameStage();
        el.customPromptInput.focus();
        sendEncrypted({ type: 'game_choice', choice: 'dare' });
      });

      el.cancelComposeBtn.addEventListener('click', () => {
        state.gamePhase = 'pick';
        renderGameStage();
      });

      el.randomSavedPromptBtn.addEventListener('click', () => {
        const matching = state.customDeck.filter(d => d.type === state.selectedType);
        if (matching.length > 0) {
          const pick = matching[Math.floor(Math.random() * matching.length)];
          el.customPromptInput.value = pick.text;
        }
      });

      el.sendPromptCardBtn.addEventListener('click', () => {
        const val = el.customPromptInput.value.trim();
        if (!val) {
          showToast(`Write a custom ${state.selectedType} or tap 'Idea from Deck'!`, '✏️', '#FFE46B');
          return;
        }
        el.customPromptInput.value = '';
        launchCard(state.selectedType, val, 'partner');
      });

      el.customPromptInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          el.sendPromptCardBtn.click();
        }
      });

      el.completeCardBtn.addEventListener('click', () => {
        if (!state.activeCard) return;
        const cType = state.activeCard.type;
        if (state.activeCard.target === 'me') {
          state.scores.me += 1;
        } else {
          state.scores.partner += 1;
        }
        const completerName = state.activeCard.target === 'me' ? state.myName : state.partnerName;
        state.turn = state.turn === 'me' ? 'partner' : 'me';
        state.activeCard = null;
        state.gamePhase = 'pick';
        renderGameStage();
        appendSystemEvent(`⭐ ${completerName} completed the ${cType.toUpperCase()}! (+1 Star)`, 'complete');
        saveSessionState();

        sendEncrypted({
          type: 'game_card_complete',
          cardType: cType,
          completedBy: 'me',
          playerName: completerName
        });
      });

      el.skipCardBtn.addEventListener('click', () => {
        state.turn = state.turn === 'me' ? 'partner' : 'me';
        state.activeCard = null;
        state.gamePhase = 'pick';
        renderGameStage();
        appendSystemEvent(`🔄 ${state.myName} skipped the card. Next turn!`, 'game');
        saveSessionState();

        sendEncrypted({
          type: 'game_card_skip',
          playerName: state.myName
        });
      });

      el.spinPencilBtn.addEventListener('click', () => {
        const nextTurn = Math.random() < 0.5 ? 'me' : 'partner';
        state.turn = nextTurn;
        state.gamePhase = 'pick';
        renderGameStage();
        const who = nextTurn === 'me' ? `Your (${state.myName})` : `${state.partnerOnline ? state.partnerName : 'Friend'}'s`;
        appendSystemEvent(`✏️ Pencil spun! It landed on ${who} turn!`, 'game');
        showToast(`Pencil landed on ${who} turn!`, '✏️', '#FFE46B');
        sendEncrypted({ type: 'spin_turn', nextTurn });
      });

      // Custom Prompt Deck Modal
      el.openCustomDeckBtn.addEventListener('click', () => {
        renderDeckList();
        el.customDeckModal.classList.remove('hidden');
      });
      el.closeDeckModalBtn.addEventListener('click', () => {
        el.customDeckModal.classList.add('hidden');
      });

      document.querySelectorAll('.deck-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          state.deckFilter = btn.dataset.filter;
          document.querySelectorAll('.deck-filter-btn').forEach(b => {
            b.classList.remove('bg-[#FFE46B]');
            b.classList.add('bg-white');
          });
          btn.classList.remove('bg-white');
          btn.classList.add('bg-[#FFE46B]');
          renderDeckList();
        });
      });

      el.addToDeckBtn.addEventListener('click', () => {
        const text = el.newDeckText.value.trim();
        const type = el.newDeckType.value;
        if (!text) {
          showToast('Please type your custom Truth or Dare first!', '✏️', '#FF8B8B');
          return;
        }
        const newItem = {
          id: 'cust_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
          type,
          text
        };
        state.customDeck.unshift(newItem);
        el.newDeckText.value = '';
        renderDeckList();
        saveSessionState();
        showToast('Saved to your notebook deck!', '📒', '#A8E6CF');
        sendEncrypted({ type: 'deck_add', item: newItem });
      });

      // Chat & Typing Events
      let myTypingTimer = null;
      let amITyping = false;

      function notifyMyTyping() {
        if (!amITyping) {
          amITyping = true;
          sendEncrypted({ type: 'typing', isTyping: true });
        }
        clearTimeout(myTypingTimer);
        myTypingTimer = setTimeout(() => {
          amITyping = false;
          sendEncrypted({ type: 'typing', isTyping: false });
        }, 1800);
      }

      el.chatMessageInput.addEventListener('input', notifyMyTyping);
      el.customPromptInput.addEventListener('input', notifyMyTyping);

      el.chatForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const text = el.chatMessageInput.value.trim();
        if (!text) return;

        el.chatMessageInput.value = '';
        clearTimeout(myTypingTimer);
        amITyping = false;
        sendEncrypted({ type: 'typing', isTyping: false });

        const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        appendChatMessage({
          sender: 'me',
          name: state.myName,
          avatar: state.myAvatar,
          text,
          time: timeStr
        });

        sendEncrypted({
          type: 'chat_msg',
          text,
          time: timeStr
        });
      });

      // Photo Sharing Events
      el.sharePhotoBtn.addEventListener('click', () => {
        el.imageUploadInput.click();
      });

      el.imageUploadInput.addEventListener('change', (e) => {
        const file = e.target.files && e.target.files[0];
        if (file) {
          compressAndSendImage(file);
        }
        el.imageUploadInput.value = '';
      });

      el.closeLightboxBtn.addEventListener('click', () => {
        el.photoLightboxModal.classList.add('hidden');
      });

      /* ----------------------------------------------------------
         13. AUTO-RESTORE SESSION IF PAGE WAS MINIMIZED / RELOADED
      ---------------------------------------------------------- */
      (async function restorePreviousSessionIfAny() {
        try {
          const raw = sessionStorage.getItem(STORAGE_KEY);
          if (!raw) return;
          const saved = JSON.parse(raw);
          if (!saved || !saved.roomCode || saved.roomCode.length !== 10) return;

          state.myName = saved.myName || 'Sketcher';
          state.myAvatar = EMOJI_TO_AVATAR_KEY[saved.myAvatar] || saved.myAvatar || 'fox';
          state.role = saved.role || 'host';
          state.roomCode = saved.roomCode;
          state.partnerName = saved.partnerName || 'Waiting for friend...';
          state.partnerAvatar = EMOJI_TO_AVATAR_KEY[saved.partnerAvatar] || saved.partnerAvatar || 'waiting';
          state.partnerToken = saved.partnerToken || null;
          state.scores = saved.scores || { me: 0, partner: 0 };
          state.turn = saved.turn || 'me';
          state.gamePhase = saved.gamePhase || 'pick';
          state.selectedType = saved.selectedType || 'truth';
          state.activeCard = saved.activeCard || null;
          if (Array.isArray(saved.customDeck) && saved.customDeck.length > 0) {
            state.customDeck = saved.customDeck;
          }
          state.chatHistory = Array.isArray(saved.chatHistory) ? saved.chatHistory : [];

          await CryptoEngine.initRoomKey(state.roomCode);
          enterRoomScreen();

          // Restore previous chat messages and photos
          state.chatHistory.forEach(item => {
            if (item.kind === 'photo') {
              appendPhotoMessage(item, false);
            } else if (item.kind === 'text') {
              appendChatMessage(item, false);
            }
          });

          startNetworkSession();
        } catch (err) {
          console.warn('Could not restore session:', err);
        }
      })();

    })();
