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
            document.body.classList.toggle('keyboard-open', isKeyboardOpen);
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

        async deriveAuthKey(roomCode) {
          const enc = new TextEncoder();
          const baseKey = await crypto.subtle.importKey(
            'raw',
            enc.encode(`TOD-AUTH-${roomCode.toUpperCase()}-V1`),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
          );
          return await crypto.subtle.deriveKey(
            {
              name: 'PBKDF2',
              salt: enc.encode(`SALT-AUTH-${roomCode.toUpperCase()}`),
              iterations: 25000,
              hash: 'SHA-256'
            },
            baseKey,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign', 'verify']
          );
        },

        async signHandshake(roomCode, pubJwk, playerToken) {
          try {
            const hmacKey = await this.deriveAuthKey(roomCode);
            const msg = `${pubJwk.x || ''}:${pubJwk.y || ''}:${playerToken || ''}`;
            const sig = await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(msg));
            return this.uint8ToBase64(new Uint8Array(sig));
          } catch (e) {
            return null;
          }
        },

        async verifyHandshake(roomCode, pubJwk, playerToken, signatureBase64) {
          try {
            if (!signatureBase64 || !pubJwk) return false;
            const hmacKey = await this.deriveAuthKey(roomCode);
            const msg = `${pubJwk.x || ''}:${pubJwk.y || ''}:${playerToken || ''}`;
            const sig = this.base64ToUint8(signatureBase64);
            return await crypto.subtle.verify('HMAC', hmacKey, sig, new TextEncoder().encode(msg));
          } catch (e) {
            return false;
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
        chatHistory: [],
        replyingTo: null
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

      async function saveSessionState() {
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
            // Strict privacy: NEVER save photo dataUrl bytes in local/session storage
            chatHistory: state.chatHistory.slice(-40).map(item => {
              if (item.kind === 'photo') {
                const safe = { ...item };
                delete safe.dataUrl;
                safe.dataUrl = null;
                return safe;
              }
              return item;
            })
          };
          // Military-grade encryption at rest: Encrypt snapshot with AES-256-GCM before saving
          if (CryptoEngine.key) {
            const encrypted = await CryptoEngine.encryptPayload(snapshot);
            if (encrypted) {
              const envelope = {
                roomCode: state.roomCode,
                iv: encrypted.iv,
                ct: encrypted.ct
              };
              sessionStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
              return;
            }
          }
          sessionStorage.setItem(STORAGE_KEY, JSON.stringify(snapshot));
        } catch (e) {
          console.warn('Could not save session snapshot:', e);
        }
      }

      function clearSessionState() {
        sessionStorage.removeItem(STORAGE_KEY);
      }

      function resetRoomSessionState() {
        CryptoEngine.key = null;
        CryptoEngine.myKeyPair = null;
        pendingImageDataUrl = null;
        activeLightboxViewOnceMsg = null;
        state.scores = { me: 0, partner: 0 };
        state.turn = 'me';
        state.gamePhase = 'pick';
        state.selectedType = 'truth';
        state.activeCard = null;
        state.customDeck = [...DEFAULT_DECK];
        state.chatHistory = [];
        state.replyingTo = null;
        state.partnerToken = null;
        state.partnerOnline = false;
        state.partnerTyping = false;
        state.partnerMicOn = false;
        state.partnerExplicitlyLeft = false;

        const chatEl = document.getElementById('chat-stream');
        if (chatEl) chatEl.innerHTML = '';

        const replyBar = document.getElementById('reply-preview-bar');
        if (replyBar) {
          replyBar.classList.add('hidden');
          replyBar.classList.remove('flex');
        }
        const chatInput = document.getElementById('chat-message-input');
        if (chatInput) {
          chatInput.value = '';
          chatInput.style.height = 'auto';
        }
        clearSessionState();
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
        e2eeLockIcon: document.getElementById('e2ee-lock-icon'),
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
        stageWaitingPrompt: document.getElementById('stage-waiting-prompt'),
        waitingPromptBadge: document.getElementById('waiting-prompt-badge'),
        waitingPromptTitle: document.getElementById('waiting-prompt-title'),
        stageComposePrompt: document.getElementById('stage-compose-prompt'),
        composeBadge: document.getElementById('compose-badge'),
        randomSavedPromptBtn: document.getElementById('random-saved-prompt-btn'),
        cancelComposeBtn: document.getElementById('cancel-compose-btn'),
        customPromptInput: document.getElementById('custom-prompt-input'),
        sendPromptCardBtn: document.getElementById('send-prompt-card-btn'),
        stageActiveCard: document.getElementById('stage-active-card'),
        activeCardBadge: document.getElementById('active-card-badge'),
        activeCardTurnPill: document.getElementById('active-card-turn-pill'),
        activeCardTarget: document.getElementById('active-card-target'),
        activeCardText: document.getElementById('active-card-text'),
        activeCardInstruction: document.getElementById('active-card-instruction'),
        activeCardWaitingPill: document.getElementById('active-card-waiting-pill'),
        skipCardBtn: document.getElementById('skip-card-btn'),
        completeCardBtn: document.getElementById('complete-card-btn'),

        // Chat & Footer
        chatTypingRow: document.getElementById('chat-typing-row'),
        chatTypingLabel: document.getElementById('chat-typing-label'),
        chatForm: document.getElementById('chat-form'),
        cameraCaptureInput: document.getElementById('camera-capture-input'),
        galleryUploadInput: document.getElementById('gallery-upload-input'),
        sharePhotoBtn: document.getElementById('share-photo-btn'),
        chatMessageInput: document.getElementById('chat-message-input'),
        sendMsgBtn: document.getElementById('send-msg-btn'),
        replyPreviewBar: document.getElementById('reply-preview-bar'),
        replyTargetName: document.getElementById('reply-target-name'),
        replyTargetSnippet: document.getElementById('reply-target-snippet'),
        cancelReplyBtn: document.getElementById('cancel-reply-btn'),

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
        lightboxViewOnceBanner: document.getElementById('lightbox-view-once-banner'),
        closeLightboxBtn: document.getElementById('close-lightbox-btn'),
        photoSourceModal: document.getElementById('photo-source-modal'),
        sourceCameraBtn: document.getElementById('source-camera-btn'),
        sourceGalleryBtn: document.getElementById('source-gallery-btn'),
        closeSourceModalBtn: document.getElementById('close-source-modal-btn'),
        photoPreviewModal: document.getElementById('photo-preview-modal'),
        previewSendImg: document.getElementById('preview-send-img'),
        previewViewOnceBadge: document.getElementById('preview-view-once-badge'),
        previewCaptionInput: document.getElementById('preview-caption-input'),
        toggleViewOnceBtn: document.getElementById('toggle-view-once-btn'),
        viewOnceLabel: document.getElementById('view-once-label'),
        viewOncePill: document.getElementById('view-once-pill'),
        cancelSendPhotoBtn: document.getElementById('cancel-send-photo-btn'),
        confirmSendPhotoBtn: document.getElementById('confirm-send-photo-btn'),
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

        // Incoming Live Voice Call (DTLS-SRTP encrypted peer-to-peer media)
        peer.on('call', (incomingCall) => {
          // Strict military-grade audio authorization check:
          // Reject immediately if not our authenticated partner, or if ECDH key exchange is not finished
          if (!dataConn || !dataConn.open || !CryptoEngine.key || !state.partnerOnline || incomingCall.peer !== dataConn.peer) {
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
            // Someone else (partner) is already holding the host ID for this room!
            // Switch to guest and connect to them
            state.role = 'guest';
            saveSessionState();
            setTimeout(() => {
              if (!isIntentionalLeave) startNetworkSession();
            }, 600);
            return;
          }

          if (err.type === 'peer-unavailable' && state.role === 'guest') {
            // Host is not online or has left. Promote this client to host so the room stays alive
            // and the partner (or creator) can rejoin using the room code!
            state.role = 'host';
            saveSessionState();
            setTimeout(() => {
              if (!isIntentionalLeave) startNetworkSession();
            }, 500);
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

          // Perform Authenticated ECDH key exchange handshake
          const myPubJwk = await CryptoEngine.generateEcdhPublicJwk();
          const authSig = await CryptoEngine.signHandshake(state.roomCode, myPubJwk, state.playerToken);
          conn.send({
            sys: 'handshake',
            pubJwk: myPubJwk,
            playerToken: state.playerToken,
            sig: authSig,
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

          // 3. Handle Authenticated Handshake & Key Exchange
          if (rawPacket.sys === 'handshake') {
            // Verify HMAC-SHA256 signature to guarantee only someone with the room code can connect!
            const isValid = await CryptoEngine.verifyHandshake(state.roomCode, rawPacket.pubJwk, rawPacket.playerToken, rawPacket.sig);
            if (!isValid) {
              showToast('Security Alert: Unauthorized connection rejected!', '🔒', '#FF8B8B');
              try { conn.close(); } catch (e) {}
              return;
            }

            const wasAlreadyKnown = state.partnerToken === rawPacket.playerToken;
            state.partnerToken = rawPacket.playerToken;
            state.partnerOnline = true;
            state.partnerExplicitlyLeft = false;

            if (rawPacket.pubJwk) {
              await CryptoEngine.completeEcdhHandshake(rawPacket.pubJwk, state.roomCode);
              updatePresenceUI();
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
          el.micToggleBtn.className = 'header-btn bg-[#A8E6CF] text-sm relative mic-live-pulse';
          el.myMicSlash.classList.add('hidden');
        } else {
          el.micToggleBtn.className = 'header-btn bg-white text-sm relative';
          el.myMicSlash.classList.remove('hidden');
        }

        // Partner Mic Badge in Header (Shown only when Live to keep header clean)
        if (state.partnerOnline && state.partnerMicOn) {
          el.partnerMicBadge.classList.remove('hidden');
          el.partnerMicBadge.classList.add('inline-flex');
          el.partnerMicBadge.className = 'inline-flex items-center text-xs shrink-0 mic-live-pulse';
          el.partnerMicIcon.textContent = '🎙️';
        } else {
          el.partnerMicBadge.classList.add('hidden');
          el.partnerMicBadge.classList.remove('inline-flex');
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
            const wasExplicitlyLeft = Boolean(state.partnerExplicitlyLeft);
            state.partnerName = (data.name || 'Friend').slice(0, 6);
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

            const isRejoin = Boolean(wasExplicitlyLeft || data.isReconnection || (!isFirstJoin && state.partnerName));
            const now = Date.now();
            const shouldAnnounce = !state._lastJoinAnnounceTime || (now - state._lastJoinAnnounceTime > 2000);

            if (shouldAnnounce) {
              state._lastJoinAnnounceTime = now;
              if (isRejoin) {
                appendSystemEvent(`✨ ${state.partnerName} rejoined the notebook!`, 'join');
                showToast(`${state.partnerName} rejoined the notebook!`, '✨', '#A8E6CF');
              } else {
                appendSystemEvent(`✨ ${state.partnerName} joined the notebook!`, 'join');
                showToast(`${state.partnerName} joined the room!`, '🎉', '#A8E6CF');
              }
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
              id: data.id,
              sender: 'partner',
              name: state.partnerName,
              avatar: state.partnerAvatar,
              text: data.text,
              time: data.time || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
              replyTo: data.replyTo || null,
              reactions: data.reactions || {}
            });
            break;
          }

          case 'photo_msg': {
            state.partnerTyping = false;
            updateTypingUI();
            appendPhotoMessage({
              id: data.id,
              sender: 'partner',
              name: state.partnerName,
              avatar: state.partnerAvatar,
              dataUrl: data.dataUrl,
              caption: data.caption || `Snap from ${state.partnerName}`,
              time: data.time || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
              replyTo: data.replyTo || null,
              reactions: data.reactions || {},
              viewOnce: Boolean(data.viewOnce),
              viewed: false
            });
            showToast(data.viewOnce ? `${state.partnerName} sent a View Once photo 👁️` : `${state.partnerName} shared a photo! 📷`, '📷', '#FFE46B');
            break;
          }

          case 'view_once_opened': {
            const item = state.chatHistory.find(m => m.id === data.id);
            if (item) {
              item.viewed = true;
              delete item.dataUrl;
              item.dataUrl = null;
            }
            updateViewOnceCardDOM(data.id, true);
            showToast(`${state.partnerName} opened your View Once photo 👁️`, '👁️', '#FFE46B');
            break;
          }

          case 'msg_reaction': {
            toggleHeartReaction(data.msgId, false, data);
            break;
          }

          case 'game_choice': {
            // Partner chose Truth or Dare!
            // RULE: Whichever player taps Truth or Dare, the OTHER player sends the card!
            state.selectedType = data.choice;
            const isTruth = data.choice === 'truth';
            appendSystemEvent(
              `🎲 ${state.partnerName} chose ${data.choice.toUpperCase()}! Write a ${data.choice} for them above!`,
              'game'
            );
            state.turn = 'partner'; // Partner is answering
            state.gamePhase = 'compose';
            gameStageSection.classList.remove('hidden');
            renderGameStage();
            el.customPromptInput.focus();
            showToast(`${state.partnerName} chose ${data.choice.toUpperCase()}! Write their card 🃏`, '🎴', isTruth ? '#7EE0C6' : '#FF8B8B');
            break;
          }

          case 'game_compose_cancel': {
            state.gamePhase = 'pick';
            renderGameStage();
            showToast(`${state.partnerName} cancelled writing`, '↩️', '#FFE46B');
            break;
          }

          case 'game_card_sent': {
            // Partner sent the card to me: I am the answerer ('me'), partner is the question asker ('partner')
            state.activeCard = {
              type: data.cardType,
              text: data.text,
              target: 'me',
              author: 'partner',
              authorName: data.authorName || state.partnerName
            };
            state.gamePhase = 'card';
            gameStageSection.classList.remove('hidden');
            renderGameStage();
            appendCardToChatStream(state.activeCard);
            saveSessionState();
            showToast(`${state.partnerName} sent your ${data.cardType.toUpperCase()} card! 🃏`, '🃏', data.cardType === 'truth' ? '#7EE0C6' : '#FF8B8B');
            break;
          }

          case 'game_card_complete': {
            state.turn = 'me'; // Next round I choose Truth or Dare
            state.activeCard = null;
            state.gamePhase = 'pick';
            renderGameStage();
            appendSystemEvent(`✓ You completed the ${data.cardType.toUpperCase()}! Next turn!`, 'complete');
            showToast(`✓ Completed the ${data.cardType.toUpperCase()}!`, '✨', '#A8E6CF');
            saveSessionState();
            break;
          }

          case 'game_card_skip': {
            state.turn = state.turn === 'me' ? 'partner' : 'me';
            state.activeCard = null;
            state.gamePhase = 'pick';
            renderGameStage();
            appendSystemEvent(`🔄 ${data.playerName} skipped the card. Next turn!`, 'game');
            showToast(`${data.playerName} skipped the card. Next turn!`, '🔄', '#FFE46B');
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
            updateConnectionBanner(`${state.partnerName} left the room. A friend can rejoin with code #${state.roomCode ? state.roomCode.slice(0, 4) + '…' : 'CODE'}`, false);
            showToast(`${state.partnerName} left the room`, '👋', '#FF8B8B');

            // If we are guest and host left, promote to host so the host or friend can rejoin with the room code!
            if (state.role === 'guest') {
              state.role = 'host';
              saveSessionState();
              setTimeout(() => {
                if (!isIntentionalLeave) startNetworkSession();
              }, 400);
            }
            break;
          }
        }
      }

      /* ----------------------------------------------------------
         8. UI RENDERING: PRESENCE, TYPING, GAME STAGE & CHAT
      ---------------------------------------------------------- */
      function updatePresenceUI() {
        el.headerRoomCode.textContent = state.roomCode ? `#${state.roomCode.slice(0, 4)}…` : '#CODE';
        if (state.roomCode && el.copyCodePill) {
          el.copyCodePill.title = `Room Code: ${state.roomCode} (Tap to copy full code)`;
        }
        el.partnerAvatarBox.innerHTML = `<div class="w-7 h-7">${getAvatarSvgHtml(state.partnerAvatar)}</div>`;
        el.partnerNameDisplay.textContent = state.partnerName;

        // Lock icon strictly shown when both sides are connected and end-to-end encryption is established
        const isE2eeActive = Boolean(state.partnerOnline && CryptoEngine.key);
        if (el.e2eeLockIcon) {
          el.e2eeLockIcon.classList.toggle('hidden', !isE2eeActive);
        }

        if (state.partnerOnline) {
          el.partnerOnlineDot.className = 'absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-[#4ADE80] border-2 border-[#2B2623]';
          el.partnerStatusText.textContent = 'Online';
          el.partnerStatusText.className = 'text-emerald-700 font-ui font-medium truncate';
          el.connectionBanner.classList.add('hidden');
        } else if (state.partnerExplicitlyLeft) {
          el.partnerOnlineDot.className = 'absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-[#FF6B6B] border-2 border-[#2B2623]';
          el.partnerStatusText.textContent = 'Left notebook';
          el.partnerStatusText.className = 'text-rose-600 font-ui font-medium truncate';
          el.connectionBanner.classList.remove('hidden');
        } else {
          el.partnerOnlineDot.className = 'absolute -bottom-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-amber-400 border-2 border-[#2B2623]';
          el.partnerStatusText.textContent = state.partnerToken ? 'Reconnecting...' : 'Waiting...';
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
        el.stagePickMode.classList.add('hidden');
        if (el.stageWaitingPrompt) el.stageWaitingPrompt.classList.add('hidden');
        el.stageComposePrompt.classList.add('hidden');
        el.stageActiveCard.classList.add('hidden');

        if (state.gamePhase === 'pick') {
          el.stagePickMode.classList.remove('hidden');
          const isMyTurn = state.turn === 'me';
          el.stagePickTitle.textContent = isMyTurn
            ? `Your Turn (${state.myName})! Pick Truth or Dare:`
            : `${state.partnerOnline ? state.partnerName : 'Friend'}'s Turn to pick Truth or Dare:`;
        } else if (state.gamePhase === 'waiting_card') {
          if (el.stageWaitingPrompt) {
            el.stageWaitingPrompt.classList.remove('hidden');
            const isTruth = state.selectedType === 'truth';
            el.waitingPromptBadge.textContent = isTruth ? '💬 YOU CHOSE TRUTH' : '⚡ YOU CHOSE DARE';
            el.waitingPromptBadge.style.backgroundColor = isTruth ? '#7EE0C6' : '#FF8B8B';
            const partnerLabel = state.partnerOnline ? state.partnerName : 'friend';
            el.waitingPromptTitle.textContent = `Waiting for ${partnerLabel} to write your card... ✏️`;
          }
        } else if (state.gamePhase === 'compose') {
          el.stageComposePrompt.classList.remove('hidden');
          const isTruth = state.selectedType === 'truth';
          const targetLabel = state.partnerOnline ? state.partnerName : 'Friend';
          el.composeBadge.textContent = isTruth
            ? `💬 Write a TRUTH for ${targetLabel}`
            : `⚡ Write a DARE for ${targetLabel}`;
          el.composeBadge.style.backgroundColor = isTruth ? '#7EE0C6' : '#FF8B8B';
          el.customPromptInput.placeholder = isTruth
            ? `Ask ${targetLabel} an honest truth question...`
            : `Challenge ${targetLabel} with a fun dare...`;
        } else if (state.gamePhase === 'card' && state.activeCard) {
          el.stageActiveCard.classList.remove('hidden');
          const isTruth = state.activeCard.type === 'truth';
          el.activeCardBadge.textContent = isTruth ? '💬 TRUTH' : '⚡ DARE';
          el.activeCardBadge.style.backgroundColor = isTruth ? '#7EE0C6' : '#FF8B8B';

          const isTargetMe = state.activeCard.target === 'me';
          const isAuthorMe = state.activeCard.author === 'me';

          const targetLabel = isTargetMe ? `You (${state.myName})` : state.partnerName;
          const authorLabel = isAuthorMe ? `You (${state.myName})` : state.partnerName;

          el.activeCardTarget.textContent = `For ${targetLabel} • Asked by ${authorLabel}`;

          // Turn info badge on card
          if (el.activeCardTurnPill) {
            if (isTargetMe) {
              el.activeCardTurnPill.textContent = '🎯 Your Turn to Answer';
              el.activeCardTurnPill.className = 'px-2.5 py-0.5 text-xs font-ui font-bold border-2 border-[#2B2623] rounded-full bg-[#7EE0C6] whitespace-nowrap';
            } else {
              el.activeCardTurnPill.textContent = `🎲 ${state.partnerName}'s Turn to Answer`;
              el.activeCardTurnPill.className = 'px-2.5 py-0.5 text-xs font-ui font-bold border-2 border-[#2B2623] rounded-full bg-[#FFE46B] whitespace-nowrap';
            }
          }

          if (isAuthorMe) {
            if (el.activeCardInstruction) {
              el.activeCardInstruction.textContent = `Waiting for ${state.partnerName} to answer in chat. Verify & finish:`;
            }
            if (el.activeCardWaitingPill) el.activeCardWaitingPill.classList.add('hidden');
            el.completeCardBtn.classList.remove('hidden');
            el.completeCardBtn.textContent = 'Done ✓';
            el.skipCardBtn.classList.remove('hidden');
            el.skipCardBtn.textContent = 'Skip 🔄';
          } else {
            if (el.activeCardInstruction) {
              el.activeCardInstruction.textContent = 'Answer in chat below, voice 🎙️, or snap 📷!';
            }
            el.completeCardBtn.classList.add('hidden');
            if (el.activeCardWaitingPill) {
              el.activeCardWaitingPill.classList.remove('hidden');
              el.activeCardWaitingPill.textContent = `⏳ Waiting for ${state.partnerName} to confirm`;
            }
            el.skipCardBtn.classList.remove('hidden');
            el.skipCardBtn.textContent = 'Pass 🔄';
          }
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

      function setReplyTarget(target) {
        state.replyingTo = target;
        if (el.replyPreviewBar && el.replyTargetName && el.replyTargetSnippet) {
          el.replyTargetName.textContent = `Replying to ${target.name}`;
          const snippet = target.text || '';
          el.replyTargetSnippet.textContent = snippet.length > 55 ? snippet.slice(0, 55) + '…' : snippet;
          el.replyPreviewBar.classList.remove('hidden');
          el.replyPreviewBar.classList.add('flex');
        }
        if (el.chatMessageInput) {
          el.chatMessageInput.focus();
        }
      }

      function cancelReply() {
        state.replyingTo = null;
        if (el.replyPreviewBar) {
          el.replyPreviewBar.classList.add('hidden');
          el.replyPreviewBar.classList.remove('flex');
        }
      }

      function scrollToMessage(msgId) {
        if (!msgId) return;
        const target = document.querySelector(`[data-msg-id="${msgId}"]`);
        if (target) {
          target.scrollIntoView({ behavior: 'smooth', block: 'center' });
          const box = target.querySelector('.msg-content-box') || target;
          box.classList.remove('animate-shake');
          void box.offsetWidth;
          box.classList.add('animate-shake');
          setTimeout(() => box.classList.remove('animate-shake'), 450);
        }
      }

      function renderReactionBadge(msgEl, reactions, msgId) {
        if (!msgEl) return;
        const contentBox = msgEl.querySelector('.msg-content-box') || msgEl;
        let badge = contentBox.querySelector('.msg-reaction-badge');

        const likers = Object.entries(reactions || {});
        if (likers.length === 0) {
          if (badge) badge.remove();
          return;
        }

        if (!badge) {
          badge = document.createElement('button');
          badge.type = 'button';
          badge.className = 'msg-reaction-badge animate-pop';
          badge.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleHeartReaction(msgId, true);
          });
          contentBox.appendChild(badge);
        }

        const myToken = state.playerToken || 'me';
        const isLikedByMe = Boolean(reactions && reactions[myToken]);
        if (isLikedByMe) {
          badge.classList.add('my-liked');
          badge.title = 'You liked this (Tap to unlike)';
        } else {
          badge.classList.remove('my-liked');
          badge.title = 'Tap to like';
        }

        // Render each liker's doodle avatar
        let avatarsHtml = '';
        likers.forEach(([tok, u]) => {
          const avatarKey = (u && u.avatar) || 'fox';
          const name = (u && u.name) || 'Friend';
          avatarsHtml += `
            <span class="reaction-avatar-mini" title="${escapeHtml(name)}">
              ${getAvatarSvgHtml(avatarKey)}
            </span>
          `;
        });

        badge.innerHTML = `
          <span class="select-none text-xs">❤️</span>
          <div class="reaction-avatar-stack flex items-center -space-x-1.5 pointer-events-none">
            ${avatarsHtml}
          </div>
        `;
      }

      function toggleHeartReaction(msgId, fromLocal = true, remoteData = null) {
        if (!msgId) return;
        const msgWrapper = document.querySelector(`[data-msg-id="${msgId}"]`);
        const contentBox = msgWrapper ? (msgWrapper.querySelector('.msg-content-box') || msgWrapper) : null;

        const historyItem = state.chatHistory.find(m => m.id === msgId);
        let reactions = {};
        if (historyItem) {
          historyItem.reactions = historyItem.reactions || {};
          reactions = historyItem.reactions;
        }

        if (fromLocal) {
          const myToken = state.playerToken || 'me';
          const alreadyLiked = Boolean(reactions[myToken]);

          if (alreadyLiked) {
            // UNLIKE: Only the user who gave the like can remove their like!
            delete reactions[myToken];
            if (historyItem) {
              historyItem.reactions = reactions;
              saveSessionState();
            }
            if (msgWrapper) {
              renderReactionBadge(msgWrapper, reactions, msgId);
            }
            sendEncrypted({
              type: 'msg_reaction',
              msgId: msgId,
              action: 'unlike',
              userToken: myToken
            });
          } else {
            // LIKE: Add my like with my doodle avatar and nickname!
            reactions[myToken] = {
              name: state.myName || 'You',
              avatar: state.myAvatar || 'fox'
            };
            if (historyItem) {
              historyItem.reactions = reactions;
              saveSessionState();
            }

            // Burst animation
            if (contentBox) {
              const burst = document.createElement('span');
              burst.className = 'animate-heart-burst select-none text-3xl pointer-events-none absolute z-30';
              burst.textContent = '❤️';
              burst.style.left = '50%';
              burst.style.top = '30%';
              contentBox.appendChild(burst);
              setTimeout(() => burst.remove(), 720);
            }

            if (navigator.vibrate) {
              try { navigator.vibrate(25); } catch (e) {}
            }

            if (msgWrapper) {
              renderReactionBadge(msgWrapper, reactions, msgId);
            }

            sendEncrypted({
              type: 'msg_reaction',
              msgId: msgId,
              action: 'like',
              userToken: myToken,
              name: state.myName,
              avatar: state.myAvatar
            });
          }
        } else if (remoteData) {
          // Incoming reaction from partner over WebRTC
          const partnerToken = remoteData.userToken || state.partnerToken || 'partner';
          if (remoteData.action === 'like') {
            reactions[partnerToken] = {
              name: remoteData.name || state.partnerName || 'Friend',
              avatar: remoteData.avatar || state.partnerAvatar || 'panda'
            };
            // Burst animation
            if (contentBox) {
              const burst = document.createElement('span');
              burst.className = 'animate-heart-burst select-none text-3xl pointer-events-none absolute z-30';
              burst.textContent = '❤️';
              burst.style.left = '50%';
              burst.style.top = '30%';
              contentBox.appendChild(burst);
              setTimeout(() => burst.remove(), 720);
            }
          } else if (remoteData.action === 'unlike') {
            delete reactions[partnerToken];
          }

          if (historyItem) {
            historyItem.reactions = reactions;
            saveSessionState();
          }
          if (msgWrapper) {
            renderReactionBadge(msgWrapper, reactions, msgId);
          }
        }
      }

      function setupMessageInteractions(wrapper, msg) {
        const swipeTarget = wrapper.querySelector('.msg-swipe-target');
        const quickReplyBtn = wrapper.querySelector('.quick-reply-btn');
        const quoteEl = wrapper.querySelector('.msg-reply-quote');
        const isMe = msg.sender === 'me';

        // Render existing reactions with doodle avatars if any
        if (msg.reactions && Object.keys(msg.reactions).length > 0) {
          renderReactionBadge(wrapper, msg.reactions, msg.id);
        }

        // Quote click scrolls smoothly to the referenced message
        if (quoteEl && msg.replyTo && msg.replyTo.id) {
          quoteEl.addEventListener('click', (e) => {
            e.stopPropagation();
            scrollToMessage(msg.replyTo.id);
          });
        }

        // Desktop hover quick-reply button
        if (quickReplyBtn) {
          quickReplyBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            setReplyTarget({
              id: msg.id,
              name: isMe ? 'You' : msg.name,
              text: msg.text || (msg.dataUrl ? '📷 Photo' : 'Card')
            });
          });
        }

        // Swipe-To-Reply and Double-Tap Gestures
        let touchStartX = 0;
        let touchStartY = 0;
        let isSwiping = false;
        let isScrolling = false;
        let lastTap = 0;
        let lastTouchReactionTime = 0;

        if (swipeTarget) {
          swipeTarget.addEventListener('touchstart', (e) => {
            if (e.touches.length !== 1) return;
            touchStartX = e.touches[0].clientX;
            touchStartY = e.touches[0].clientY;
            isSwiping = false;
            isScrolling = false;
            swipeTarget.style.transition = 'none';
          }, { passive: true });

          swipeTarget.addEventListener('touchmove', (e) => {
            if (isScrolling || e.touches.length !== 1) return;
            const touchX = e.touches[0].clientX;
            const touchY = e.touches[0].clientY;
            const dx = touchX - touchStartX;
            const dy = touchY - touchStartY;

            if (!isSwiping) {
              if (Math.abs(dy) > 8 && Math.abs(dy) > Math.abs(dx)) {
                isScrolling = true;
                return;
              }
              if (dx > 8 && Math.abs(dx) > Math.abs(dy)) {
                isSwiping = true;
              }
            }

            if (isSwiping && dx > 0) {
              const moveX = Math.min(dx * 0.45, 55);
              swipeTarget.style.transform = `translateX(${moveX}px)`;
              if (moveX >= 32) {
                wrapper.classList.add('swipe-reply-active');
              } else {
                wrapper.classList.remove('swipe-reply-active');
              }
            }
          }, { passive: true });

          swipeTarget.addEventListener('touchend', (e) => {
            if (isSwiping) {
              const triggered = wrapper.classList.contains('swipe-reply-active');
              swipeTarget.style.transition = 'transform 0.22s cubic-bezier(0.2, 0, 0, 1)';
              swipeTarget.style.transform = 'translateX(0px)';
              wrapper.classList.remove('swipe-reply-active');
              lastTap = 0;

              if (triggered) {
                if (navigator.vibrate) try { navigator.vibrate(20); } catch (err) {}
                setReplyTarget({
                  id: msg.id,
                  name: isMe ? 'You' : msg.name,
                  text: msg.text || (msg.dataUrl ? '📷 Photo' : 'Card')
                });
              }
              return;
            }

            if (isScrolling) {
              lastTap = 0;
              return;
            }

            // Verify finger didn't drag/scroll
            const endTouch = e.changedTouches && e.changedTouches[0];
            const moveDist = endTouch ? Math.hypot(endTouch.clientX - touchStartX, endTouch.clientY - touchStartY) : 0;
            if (moveDist > 14) {
              lastTap = 0;
              return;
            }

            // Double tap heart detection on touch (generous 450ms window)
            const now = Date.now();
            const timeDiff = now - lastTap;
            if (timeDiff > 40 && timeDiff < 450) {
              lastTap = 0;
              lastTouchReactionTime = now;
              if (e.cancelable) e.preventDefault();
              toggleHeartReaction(msg.id, true);
            } else {
              lastTap = now;
            }
          });

          // Desktop double click for heart reaction (prevent synthetic mobile dblclick double-toggle)
          swipeTarget.addEventListener('dblclick', (e) => {
            if (Date.now() - lastTouchReactionTime < 700) {
              e.preventDefault();
              return;
            }
            e.preventDefault();
            toggleHeartReaction(msg.id, true);
          });
        }
      }

      function appendChatMessage(msg, save = true) {
        msg.id = msg.id || ('msg_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7));
        msg.reactions = msg.reactions || {};
        const isMe = msg.sender === 'me';
        const wrapper = document.createElement('div');
        wrapper.className = `msg-swipe-wrapper relative flex items-end gap-2 ${isMe ? 'flex-row-reverse' : 'flex-row'} animate-pop`;
        wrapper.setAttribute('data-msg-id', msg.id);

        const bubbleBg = isMe ? 'bg-[#FFF9DB]' : 'bg-white';

        let replyHtml = '';
        if (msg.replyTo && msg.replyTo.text) {
          replyHtml = `
            <div class="msg-reply-quote mb-1.5 px-2.5 py-1 bg-black/5 hover:bg-black/10 border-l-2 border-[#2B2623] rounded text-xs select-none cursor-pointer transition-colors">
              <span class="font-bold text-[#2B2623] block text-[10px] leading-tight">↩️ ${escapeHtml(msg.replyTo.name)}</span>
              <span class="text-[#6E655F] font-hand text-xs truncate block leading-tight">${escapeHtml(msg.replyTo.text)}</span>
            </div>
          `;
        }

        wrapper.innerHTML = `
          <!-- Swipe Reply Cue -->
          <div class="swipe-reply-cue">↩️</div>

          <div class="w-8 h-8 p-1 sketch-pill bg-white flex items-center justify-center shrink-0 select-none">
            ${getAvatarSvgHtml(msg.avatar)}
          </div>

          <div class="msg-swipe-target max-w-[76%]">
            <div class="msg-content-box relative ${bubbleBg} sketch-box px-3.5 py-2">
              ${replyHtml}
              <div class="flex items-center ${isMe ? 'justify-end' : 'justify-between'} gap-3 text-[11px] font-ui text-[#6E655F] mb-0.5">
                ${!isMe ? `<span class="font-semibold text-[#2B2623]">${escapeHtml(msg.name)}</span>` : ''}
                <span>${escapeHtml(msg.time)}</span>
              </div>
              <p class="text-base font-hand text-[#2B2623] leading-snug break-words whitespace-pre-wrap">${escapeHtml(msg.text)}</p>
            </div>
          </div>

          <!-- Quick reply for desktop hover -->
          <button type="button" class="quick-reply-btn sketch-btn w-6 h-6 rounded-full bg-[#FFE46B] text-[11px] flex items-center justify-center shrink-0 self-center" title="Reply">
            ↩️
          </button>
        `;

        setupMessageInteractions(wrapper, msg);

        chatStream.appendChild(wrapper);
        scrollToBottom();

        if (save) {
          state.chatHistory.push({ kind: 'text', ...msg });
          saveSessionState();
        }
      }

      let pendingImageDataUrl = null;
      let pendingViewOnce = false;
      let activeLightboxViewOnceMsg = null;

      function updateViewOnceToggleUI(isOn) {
        if (!el.toggleViewOnceBtn) return;
        if (isOn) {
          el.toggleViewOnceBtn.classList.remove('bg-white');
          el.toggleViewOnceBtn.classList.add('bg-[#FFF9DB]');
          if (el.viewOnceLabel) el.viewOnceLabel.textContent = 'View Once Photo: ON 👁️';
          if (el.viewOncePill) {
            el.viewOncePill.textContent = 'VIEW ONCE';
            el.viewOncePill.className = 'px-2 py-0.5 rounded-full border-2 border-[#2B2623] text-[10px] font-bold bg-[#FFE46B] text-[#2B2623]';
          }
          if (el.previewViewOnceBadge) el.previewViewOnceBadge.classList.remove('hidden');
        } else {
          el.toggleViewOnceBtn.classList.remove('bg-[#FFF9DB]');
          el.toggleViewOnceBtn.classList.add('bg-white');
          if (el.viewOnceLabel) el.viewOnceLabel.textContent = 'View Once Photo: OFF';
          if (el.viewOncePill) {
            el.viewOncePill.textContent = 'OFF';
            el.viewOncePill.className = 'px-2 py-0.5 rounded-full border border-[#2B2623] text-[10px] font-bold bg-gray-100 text-[#2B2623]';
          }
          if (el.previewViewOnceBadge) el.previewViewOnceBadge.classList.add('hidden');
        }
      }

      function updateViewOnceCardDOM(msgId, viewed) {
        const wrapper = document.querySelector(`[data-msg-id="${msgId}"]`);
        if (!wrapper) return;
        const isMe = wrapper.classList.contains('flex-row-reverse');
        const card = wrapper.querySelector('.view-once-card');
        if (!card) return;

        const iconCircle = card.querySelector('.view-once-icon-circle');
        if (iconCircle) {
          iconCircle.classList.remove('bg-[#FFE46B]');
          iconCircle.classList.add('bg-gray-100');
          iconCircle.textContent = '✓';
        }
        const titleEl = card.querySelector('.view-once-title');
        if (titleEl) {
          titleEl.textContent = isMe ? 'View Once (Opened)' : 'View Once (Expired)';
        }
        const subEl = card.querySelector('.view-once-sub');
        if (subEl) {
          subEl.textContent = isMe ? `Opened by ${state.partnerName || 'friend'} 👁️` : 'Opened • Expired';
        }
      }

      function closePhotoLightbox() {
        if (activeLightboxViewOnceMsg) {
          const msg = activeLightboxViewOnceMsg;
          activeLightboxViewOnceMsg = null;

          // Only recipient can open View Once into lightbox; shred and notify sender
          msg.viewed = true;
          delete msg.dataUrl;
          msg.dataUrl = null;

          updateViewOnceCardDOM(msg.id, true);

          sendEncrypted({
            type: 'view_once_opened',
            id: msg.id
          });
          showToast('View Once photo expired & shredded from memory 👁️', '🔒', '#FFE46B');
        }
        if (el.lightboxImg) el.lightboxImg.src = '';
        if (el.lightboxViewOnceBanner) el.lightboxViewOnceBanner.classList.add('hidden');
        if (el.photoLightboxModal) el.photoLightboxModal.classList.add('hidden');
      }

      function appendPhotoMessage(msg, save = true) {
        msg.id = msg.id || ('msg_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7));
        msg.reactions = msg.reactions || {};
        const isMe = msg.sender === 'me';
        const wrapper = document.createElement('div');
        wrapper.className = `msg-swipe-wrapper relative flex items-end gap-2 ${isMe ? 'flex-row-reverse' : 'flex-row'} animate-pop`;
        wrapper.setAttribute('data-msg-id', msg.id);

        let replyHtml = '';
        if (msg.replyTo && msg.replyTo.text) {
          replyHtml = `
            <div class="msg-reply-quote mb-1.5 px-2.5 py-1 bg-black/5 hover:bg-black/10 border-l-2 border-[#2B2623] rounded text-xs select-none cursor-pointer transition-colors">
              <span class="font-bold text-[#2B2623] block text-[10px] leading-tight">↩️ ${escapeHtml(msg.replyTo.name)}</span>
              <span class="text-[#6E655F] font-hand text-xs truncate block leading-tight">${escapeHtml(msg.replyTo.text)}</span>
            </div>
          `;
        }

        if (msg.viewOnce) {
          // VIEW ONCE PHOTO: Never render image inline in chat! Private locked sketch badge.
          const isExpired = Boolean(msg.viewed || (!isMe && !msg.dataUrl));
          wrapper.innerHTML = `
            <!-- Swipe Reply Cue -->
            <div class="swipe-reply-cue">↩️</div>

            <div class="w-8 h-8 p-1 sketch-pill bg-white flex items-center justify-center shrink-0 select-none">
              ${getAvatarSvgHtml(msg.avatar)}
            </div>

            <div class="msg-swipe-target max-w-[260px]">
              <div class="msg-content-box view-once-card sketch-box ${isMe ? 'bg-[#FFF9DB]' : 'bg-white'} p-2.5 select-none ${isMe ? 'cursor-default' : 'cursor-pointer active:scale-95 transition-transform'}">
                ${replyHtml}
                <div class="flex items-center gap-2.5">
                  <div class="view-once-icon-circle w-9 h-9 rounded-full border-2 border-[#2B2623] ${isExpired ? 'bg-gray-100' : 'bg-[#FFE46B]'} flex items-center justify-center text-lg shrink-0 font-bold">
                    ${isExpired ? '✓' : '👁️'}
                  </div>
                  <div class="min-w-0 flex-1">
                    <div class="flex items-center justify-between text-[11px] font-ui text-[#6E655F]">
                      <span class="view-once-title font-bold text-[#2B2623] uppercase tracking-wide">
                        ${isExpired ? (isMe ? 'View Once (Opened)' : 'View Once (Expired)') : 'View Once Photo'}
                      </span>
                      <span>${escapeHtml(msg.time)}</span>
                    </div>
                    <p class="view-once-sub text-xs font-hand text-[#2B2623] truncate mt-0.5">
                      ${isExpired
                        ? (isMe ? `Opened by ${state.partnerName || 'friend'} 👁️` : 'Opened • Expired')
                        : (isMe ? `Sent • Waiting for ${state.partnerName || 'friend'} 🔒` : 'Tap to open • Disappears 👁️')
                      }
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <!-- Quick reply for desktop hover -->
            <button type="button" class="quick-reply-btn sketch-btn w-6 h-6 rounded-full bg-[#FFE46B] text-[11px] flex items-center justify-center shrink-0 self-center" title="Reply">
              ↩️
            </button>
          `;

          const viewOnceCard = wrapper.querySelector('.view-once-card');
          if (viewOnceCard) {
            viewOnceCard.addEventListener('click', () => {
              // SENDER cannot open View Once photo (WhatsApp standard)
              if (isMe) {
                if (msg.viewed) {
                  showToast(`Opened by ${state.partnerName || 'friend'} • Permanently deleted 🔒`, '👁️', '#FFE46B');
                } else {
                  showToast(`View Once photo sent. Only ${state.partnerName || 'your friend'} can open it! 🔒`, '🔒', '#FFE46B');
                }
                return;
              }

              // RECIPIENT ONLY can open
              if (msg.viewed || !msg.dataUrl) {
                showToast('This View Once photo has expired and was permanently shredded', '🔒', '#FF8B8B');
                return;
              }

              // Open in Lightbox (Recipient)
              el.lightboxImg.src = msg.dataUrl;
              el.lightboxCaption.textContent = msg.caption || `Snap • ${msg.time}`;
              if (el.lightboxViewOnceBanner) {
                el.lightboxViewOnceBanner.classList.remove('hidden');
                const bannerText = el.lightboxViewOnceBanner.querySelector('span:last-child');
                if (bannerText) {
                  bannerText.textContent = 'VIEW ONCE PHOTO — Disappears immediately after closing';
                }
              }
              activeLightboxViewOnceMsg = msg;
              el.photoLightboxModal.classList.remove('hidden');
            });
          }
        } else {
          // REGULAR PHOTO: Classic sketch polaroid frame
          wrapper.innerHTML = `
            <!-- Swipe Reply Cue -->
            <div class="swipe-reply-cue">↩️</div>

            <div class="w-8 h-8 p-1 sketch-pill bg-white flex items-center justify-center shrink-0 select-none">
              ${getAvatarSvgHtml(msg.avatar)}
            </div>

            <div class="msg-swipe-target max-w-[240px]">
              <div class="msg-content-box polaroid-frame cursor-pointer group relative">
                ${replyHtml}
                <div class="flex items-center ${isMe ? 'justify-end' : 'justify-between'} text-[11px] font-ui text-[#6E655F] mb-1">
                  ${!isMe ? `<span class="font-semibold text-[#2B2623]">📷 ${escapeHtml(msg.name)}</span>` : ''}
                  <span>${escapeHtml(msg.time)}</span>
                </div>
                <img src="${msg.dataUrl || ''}" alt="Shared photo" draggable="false" oncontextmenu="return false;" class="w-full max-h-48 object-cover rounded border border-[#2B2623]" />
                <p class="font-title text-xl text-center text-[#2B2623] mt-1 leading-none">${escapeHtml(msg.caption || 'Tap to view full size')}</p>
              </div>
            </div>

            <!-- Quick reply for desktop hover -->
            <button type="button" class="quick-reply-btn sketch-btn w-6 h-6 rounded-full bg-[#FFE46B] text-[11px] flex items-center justify-center shrink-0 self-center" title="Reply">
              ↩️
            </button>
          `;

          const polaroidImg = wrapper.querySelector('img');
          let polaroidClickTimer = null;
          if (polaroidImg) {
            polaroidImg.addEventListener('click', (e) => {
              if (e.detail === 2) {
                clearTimeout(polaroidClickTimer);
                return;
              }
              polaroidClickTimer = setTimeout(() => {
                if (!msg.dataUrl) {
                  showToast('Photo expired (not stored in memory)', '📷', '#FFE46B');
                  return;
                }
                el.lightboxImg.src = msg.dataUrl;
                el.lightboxCaption.textContent = `${isMe ? 'Shared by You' : 'Shared by ' + msg.name} • ${msg.time}`;
                if (el.lightboxViewOnceBanner) el.lightboxViewOnceBanner.classList.add('hidden');
                activeLightboxViewOnceMsg = null;
                el.photoLightboxModal.classList.remove('hidden');
              }, 240);
            });
          }
        }

        setupMessageInteractions(wrapper, msg);

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
      function handleSelectedImageFile(file) {
        if (!file || !file.type.startsWith('image/')) {
          showToast('Please select a valid photo file', '📷', '#FF8B8B');
          return;
        }

        showToast('Preparing your snap...', '📷', '#FFE46B');

        const reader = new FileReader();
        reader.onload = (e) => {
          const img = new Image();
          img.onload = () => {
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
            pendingImageDataUrl = compressedDataUrl;
            pendingViewOnce = false;

            if (el.previewSendImg) el.previewSendImg.src = compressedDataUrl;
            if (el.previewCaptionInput) el.previewCaptionInput.value = '';
            updateViewOnceToggleUI(false);
            if (el.photoPreviewModal) el.photoPreviewModal.classList.remove('hidden');
          };
          img.src = e.target.result;
        };
        reader.readAsDataURL(file);
      }

      async function sendPreparedPhoto(dataUrl, caption, viewOnce = false) {
        const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const replyTarget = state.replyingTo;
        cancelReply();
        const newMsgId = 'msg_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);

        appendPhotoMessage({
          id: newMsgId,
          sender: 'me',
          name: state.myName,
          avatar: state.myAvatar,
          dataUrl: dataUrl,
          caption: caption || (viewOnce ? 'View Once Snap 👁️' : 'Notebook Snap ✨'),
          time: timeStr,
          replyTo: replyTarget,
          viewOnce: viewOnce,
          viewed: false
        });

        const sent = await sendEncrypted({
          type: 'photo_msg',
          id: newMsgId,
          dataUrl: dataUrl,
          caption: caption || (viewOnce ? `View Once from ${state.myName} 👁️` : `Snap from ${state.myName} ✨`),
          time: timeStr,
          replyTo: replyTarget,
          viewOnce: viewOnce
        });

        if (viewOnce) {
          // Zero-trace security: Immediately shred image bytes from sender memory
          // Sender cannot open a sent View Once photo
          const selfMsg = state.chatHistory.find(m => m.id === newMsgId);
          if (selfMsg) {
            delete selfMsg.dataUrl;
            selfMsg.dataUrl = null;
          }
        }

        if (!sent && !state.partnerOnline) {
          showToast('Photo queued! Friend will receive it when connected.', '📷', '#FFE46B');
        }
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

        if (state.gamePhase === 'waiting_card') {
          showToast(`Waiting for ${state.partnerName} to send your card!`, '⏳', '#FFE46B');
          return;
        }

        // I wrote and sent this card to partner:
        // author is 'me', target is 'partner'
        state.activeCard = {
          type: cardType,
          text: cleanText,
          target: 'partner',
          author: 'me',
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
        let nameVal = el.playerNameInput.value.trim();
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
        if (nameVal.length > 6) {
          nameVal = nameVal.slice(0, 6);
          el.playerNameInput.value = nameVal;
        }
        return nameVal;
      }

      el.playerNameInput.addEventListener('input', () => {
        if (el.playerNameInput.value.length > 6) {
          el.playerNameInput.value = el.playerNameInput.value.slice(0, 6);
        }
        if (el.playerNameInput.value.trim()) {
          el.playerNameInput.style.borderColor = '';
          el.playerNameInput.style.backgroundColor = '';
        }
      });

      // Create 10-Char Room
      el.createRoomBtn.addEventListener('click', async () => {
        const nameVal = validateNickname();
        if (!nameVal) return;

        resetRoomSessionState();

        state.myName = nameVal;
        state.role = 'host';
        state.roomCode = generate10CharCode();
        state.partnerName = 'Waiting for friend...';
        state.partnerAvatar = 'waiting';

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

        resetRoomSessionState();

        state.myName = nameVal;
        state.role = 'guest';
        state.roomCode = code;
        state.partnerName = 'Connecting to friend...';
        state.partnerAvatar = 'waiting';
        state.turn = 'partner';

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
        resetRoomSessionState();

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
      function handleChooseTruthOrDare(type) {
        state.selectedType = type;
        // User who clicked enters waiting_card state! Partner will compose and send the card!
        state.gamePhase = 'waiting_card';
        renderGameStage();

        const typeUpper = type.toUpperCase();
        appendSystemEvent(`🎲 You chose ${typeUpper}! Waiting for ${state.partnerOnline ? state.partnerName : 'friend'} to write your question...`, 'game');
        showToast(`You chose ${typeUpper}! Waiting for ${state.partnerName}...`, type === 'truth' ? '💬' : '⚡', type === 'truth' ? '#7EE0C6' : '#FF8B8B');

        sendEncrypted({
          type: 'game_choice',
          choice: type,
          pickerName: state.myName
        });
      }

      el.chooseTruthBtn.addEventListener('click', () => handleChooseTruthOrDare('truth'));
      el.chooseDareBtn.addEventListener('click', () => handleChooseTruthOrDare('dare'));

      el.cancelComposeBtn.addEventListener('click', () => {
        state.gamePhase = 'pick';
        renderGameStage();
        sendEncrypted({ type: 'game_compose_cancel' });
      });

      if (el.randomSavedPromptBtn) {
        el.randomSavedPromptBtn.addEventListener('click', () => {
          const matching = state.customDeck.filter(d => d.type === state.selectedType);
          if (matching.length > 0) {
            const pick = matching[Math.floor(Math.random() * matching.length)];
            el.customPromptInput.value = pick.text;
          }
        });
      }

      el.sendPromptCardBtn.addEventListener('click', () => {
        const val = el.customPromptInput.value.trim();
        if (!val) {
          showToast(`Write a custom ${state.selectedType} first!`, '✏️', '#FFE46B');
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

        if (state.activeCard.author !== 'me') {
          showToast('Only the person who asked the question can confirm completion!', '⚠️', '#FF8B8B');
          return;
        }

        const cType = state.activeCard.type;
        const winnerName = state.partnerName;

        // Next turn goes to the partner who just answered!
        state.turn = 'partner';
        state.activeCard = null;
        state.gamePhase = 'pick';
        renderGameStage();
        appendSystemEvent(`✓ ${winnerName} completed the ${cType.toUpperCase()}! Next turn!`, 'complete');
        saveSessionState();

        sendEncrypted({
          type: 'game_card_complete',
          cardType: cType,
          winnerName: winnerName,
          authorName: state.myName
        });
      });

      el.skipCardBtn.addEventListener('click', () => {
        if (!state.activeCard) return;
        const cType = state.activeCard.type;
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

      if (el.spinPencilBtn) {
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
      }

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

      function adjustChatInputHeight() {
        if (!el.chatMessageInput) return;
        el.chatMessageInput.style.height = 'auto';
        const newHeight = Math.min(el.chatMessageInput.scrollHeight, 110);
        el.chatMessageInput.style.height = Math.max(newHeight, 44) + 'px';
      }

      el.chatMessageInput.addEventListener('input', () => {
        notifyMyTyping();
        adjustChatInputHeight();
      });
      el.customPromptInput.addEventListener('input', notifyMyTyping);

      el.chatMessageInput.addEventListener('keydown', (e) => {
        // Desktop / Hardware keyboard: Enter sends message, Shift+Enter makes newline
        const isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
        if (e.key === 'Enter' && !e.shiftKey && !isTouch) {
          e.preventDefault();
          el.chatForm.dispatchEvent(new Event('submit', { cancelable: true }));
        }
      });

      // Prevent send button click from taking focus away from textarea, which closes mobile virtual keyboard
      if (el.sendMsgBtn) {
        el.sendMsgBtn.addEventListener('pointerdown', (e) => {
          e.preventDefault();
        });
      }

      el.chatForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const text = el.chatMessageInput.value.trim();
        if (!text) return;

        el.chatMessageInput.value = '';
        el.chatMessageInput.style.height = '44px';
        clearTimeout(myTypingTimer);
        amITyping = false;
        sendEncrypted({ type: 'typing', isTyping: false });

        // Keep mobile keyboard open for continuous chat typing
        el.chatMessageInput.focus({ preventScroll: true });

        const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const replyTarget = state.replyingTo;
        cancelReply();
        const newMsgId = 'msg_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);

        appendChatMessage({
          id: newMsgId,
          sender: 'me',
          name: state.myName,
          avatar: state.myAvatar,
          text,
          time: timeStr,
          replyTo: replyTarget
        });

        sendEncrypted({
          type: 'chat_msg',
          id: newMsgId,
          text,
          time: timeStr,
          replyTo: replyTarget
        });
      });

      if (el.cancelReplyBtn) {
        el.cancelReplyBtn.addEventListener('click', cancelReply);
      }

      // Photo Sharing Events (Camera vs Gallery & View Once Modal)
      if (el.sharePhotoBtn) {
        el.sharePhotoBtn.addEventListener('click', () => {
          if (el.photoSourceModal) el.photoSourceModal.classList.remove('hidden');
        });
      }

      if (el.sourceCameraBtn) {
        el.sourceCameraBtn.addEventListener('click', () => {
          if (el.photoSourceModal) el.photoSourceModal.classList.add('hidden');
          if (el.cameraCaptureInput) el.cameraCaptureInput.click();
        });
      }

      if (el.sourceGalleryBtn) {
        el.sourceGalleryBtn.addEventListener('click', () => {
          if (el.photoSourceModal) el.photoSourceModal.classList.add('hidden');
          if (el.galleryUploadInput) el.galleryUploadInput.click();
        });
      }

      if (el.closeSourceModalBtn) {
        el.closeSourceModalBtn.addEventListener('click', () => {
          if (el.photoSourceModal) el.photoSourceModal.classList.add('hidden');
        });
      }

      if (el.cameraCaptureInput) {
        el.cameraCaptureInput.addEventListener('change', (e) => {
          const file = e.target.files && e.target.files[0];
          if (file) handleSelectedImageFile(file);
          el.cameraCaptureInput.value = '';
        });
      }

      if (el.galleryUploadInput) {
        el.galleryUploadInput.addEventListener('change', (e) => {
          const file = e.target.files && e.target.files[0];
          if (file) handleSelectedImageFile(file);
          el.galleryUploadInput.value = '';
        });
      }

      if (el.toggleViewOnceBtn) {
        el.toggleViewOnceBtn.addEventListener('click', () => {
          pendingViewOnce = !pendingViewOnce;
          updateViewOnceToggleUI(pendingViewOnce);
        });
      }

      if (el.cancelSendPhotoBtn) {
        el.cancelSendPhotoBtn.addEventListener('click', () => {
          if (el.photoPreviewModal) el.photoPreviewModal.classList.add('hidden');
          pendingImageDataUrl = null;
          if (el.previewSendImg) el.previewSendImg.src = '';
        });
      }

      if (el.confirmSendPhotoBtn) {
        el.confirmSendPhotoBtn.addEventListener('click', () => {
          if (!pendingImageDataUrl) return;
          const caption = el.previewCaptionInput ? el.previewCaptionInput.value.trim() : '';
          const viewOnce = pendingViewOnce;
          if (el.photoPreviewModal) el.photoPreviewModal.classList.add('hidden');
          sendPreparedPhoto(pendingImageDataUrl, caption, viewOnce);
          pendingImageDataUrl = null;
          if (el.previewSendImg) el.previewSendImg.src = '';
        });
      }

      // Close Lightbox (with view once shredding)
      if (el.closeLightboxBtn) {
        el.closeLightboxBtn.addEventListener('click', closePhotoLightbox);
      }
      if (el.photoLightboxModal) {
        el.photoLightboxModal.addEventListener('click', (e) => {
          if (e.target === el.photoLightboxModal) closePhotoLightbox();
        });
      }

      /* ----------------------------------------------------------
         13. AUTO-RESTORE SESSION IF PAGE WAS MINIMIZED / RELOADED
      ---------------------------------------------------------- */
      (async function restorePreviousSessionIfAny() {
        try {
          const raw = sessionStorage.getItem(STORAGE_KEY);
          if (!raw) return;
          const parsed = JSON.parse(raw);
          if (!parsed || !parsed.roomCode) return;

          let saved = parsed;
          if (parsed.iv && parsed.ct) {
            // Decrypt AES-256-GCM encrypted snapshot
            await CryptoEngine.initRoomKey(parsed.roomCode);
            saved = await CryptoEngine.decryptPayload({ iv: parsed.iv, ct: parsed.ct });
          }
          if (!saved || !saved.roomCode || saved.roomCode.length !== 10) return;

          state.myName = (saved.myName || 'Sketcher').slice(0, 6);
          if (el.playerNameInput) el.playerNameInput.value = state.myName;
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
