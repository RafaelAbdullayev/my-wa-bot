// whatsapp_client.js - ИСПРАВЛЕННАЯ ВЕРСИЯ
const { default: makeWASocket, useMultiFileAuthState, DisconnectReason } = require('@whiskeysockets/baileys');
const qrcode = require('qrcode-terminal');
const axios = require('axios');
const { Boom } = require('@hapi/boom');

// Python serverinin ünvanı
const AI_SERVER_URL = 'http://127.0.0.1:8000/moderate';

// Qrupa mesaj göndərmək üçün funksiya
async function sendGroupMessage(sock, groupId, messageContent, senderMention) {
    try {
        let textToSend = messageContent;
        if (senderMention) {
            // Düzgün mention formatı
            const mentionId = senderMention.includes('@s.whatsapp.net') ? senderMention : senderMention + '@s.whatsapp.net';
            // Təkrarlanan mention-ları təmizlə
            textToSend = messageContent.replace(/@\d+/g, '').trim();
            textToSend = `@${mentionId.split('@')[0]} ${textToSend}`;
            
            await sock.sendMessage(groupId, { 
                text: textToSend, 
                mentions: [mentionId]
            });
            console.log(`🤖 Bot cavabı: ${textToSend}`);
        } else {
            await sock.sendMessage(groupId, { text: messageContent });
            console.log(`🤖 Bot cavabı: ${messageContent}`);
        }
    } catch (error) {
        console.error('❌ Mesaj göndərilmədi:', error);
    }
}

// ===========================================================
// 🔥 DÜZGÜN MESAJ SİLMƏ FUNKSİYASI - YENİ VERSİYA
// ===========================================================
async function deleteMessage(sock, chatId, messageKey) {
    try {
        // Mesajın silinə biləcəyini yoxlayaq
        if (!messageKey || !messageKey.id) {
            console.log('⚠️ Mesaj ID-si tapılmadı');
            return false;
        }

        console.log('🗑️ Mesaj silinir... ID:', messageKey.id);
        
        // WhatsApp-da mesaj silmə - DÜZGÜN FORMAT
        await sock.sendMessage(chatId, { 
            delete: messageKey  // Bu format işləməlidir
        });
        
        console.log('✅ Mesaj UĞURLA silindi!');
        return true;
    } catch (error) {
        console.error('❌ Mesaj silinmədi. Xəta:', error.message);
        
        // Alternativ silmə üsulu
        try {
            console.log('🔄 Alternativ silmə üsulu sınanır...');
            
            // Alternativ format
            const deleteMessage = {
                remoteJid: chatId,
                fromMe: false,
                id: messageKey.id,
                participant: messageKey.participant || chatId
            };
            
            await sock.sendMessage(chatId, {
                delete: deleteMessage
            });
            
            console.log('✅ Alternativ üsulla silindi!');
            return true;
        } catch (e) {
            console.error('❌ Alternativ silmə də işləmədi:', e.message);
            return false;
        }
    }
}

async function connectToWhatsApp() {
    console.log('🤖 WhatsApp AI Moderator (Azərbaycan)');
    console.log('====================================\n');
    console.log('WhatsApp botu işə salınır...');
    
    const { state, saveCreds } = await useMultiFileAuthState('auth_info_baileys');
    
    const sock = makeWASocket({
        printQRInTerminal: false,
        auth: state,
        defaultQueryTimeoutMs: undefined,
        syncFullHistory: false,
        markOnlineOnConnect: true,
        emitOwnEvents: false
    });

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect, qr } = update;
        
        if (qr) {
            console.log('\n🔐 Telefonunuzla QR kodu skan edin (ehtiyat nömrə!):\n');
            qrcode.generate(qr, { small: true });
        }
        
        if (connection === 'close') {
            const shouldReconnect = (lastDisconnect.error)?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log('❌ Bağlantı qopdu', lastDisconnect.error?.message);
            
            if (shouldReconnect) {
                console.log('🔄 Yenidən bağlanılır...');
                setTimeout(() => connectToWhatsApp(), 5000);
            }
        } else if (connection === 'open') {
            console.log('✅ Bot WhatsApp-a UĞURLA bağlandı!');
            console.log('📱 Bot işləyir və mesajları gözləyir...\n');
            console.log('⚠️ QEYD: Mesajları silmək üçün bot admin olmalıdır!');
        }
    });

    sock.ev.on('messages.upsert', async ({ messages }) => {
        const m = messages[0];
        
        // Öz mesajlarımızı, statusları və boş mesajları iqnor et
        if (!m.message || m.key.fromMe || m.key.remoteJid === 'status@broadcast') {
            return;
        }

        const remoteJid = m.key.remoteJid;
        const isGroup = remoteJid.endsWith('@g.us');
        const sender = isGroup ? m.key.participant : m.key.remoteJid;
        
        // Mesaj mətnini əldə et
        let messageText = '';
        if (m.message.conversation) {
            messageText = m.message.conversation;
        } else if (m.message.extendedTextMessage?.text) {
            messageText = m.message.extendedTextMessage.text;
        } else if (m.message.imageMessage?.caption) {
            messageText = m.message.imageMessage.caption;
        }

        if (!messageText || !messageText.trim()) return;

        const chatName = isGroup ? remoteJid.split('@')[0] : 'şəxsi';
        console.log(`\n📩 [${chatName}] ${sender.split('@')[0]}: ${messageText.substring(0, 50)}${messageText.length > 50 ? '...' : ''}`);

        try {
            // AI serverə sorğu göndər
            const response = await axios.post(AI_SERVER_URL, {
                message: messageText,
                sender: sender,
                chat_id: remoteJid,
                is_group: isGroup
            }, {
                timeout: 15000,
                headers: { 'Content-Type': 'application/json' }
            });

            const decision = response.data;
            console.log(`🤖 AI qərarı: ${decision.action} - ${decision.reason}`);

            // ===================================================
            // 🔥 MESAJ SİLMƏ - ƏN VACİB HİSSƏ
            // ===================================================
            if (decision.action === 'delete' || decision.action === 'ban') {
                console.log('⏳ Mesaj silinməyə çalışılır...');
                
                // Mesajı sil
                const deleted = await deleteMessage(sock, remoteJid, m.key);
                
                if (deleted) {
                    console.log('✅ Mesaj silindi!');
                    
                    // Xəbərdarlıq mesajı varsa göndər (1 saniyə gözlə)
                    if (decision.response_text) {
                        setTimeout(async () => {
                            await sendGroupMessage(sock, remoteJid, decision.response_text, sender);
                        }, 1000);
                    }
                } else {
                    console.log('⚠️ Mesaj silinə bilmədi, amma xəbərdarlıq göndərilir');
                    // Silmək mümkün olmasa da, xəbərdarlığı göndər
                    if (decision.response_text) {
                        await sendGroupMessage(sock, remoteJid, decision.response_text, sender);
                    }
                }
            }
            // Yalnız xəbərdarlıq (silinməyəcək)
            else if (decision.action === 'warn' && decision.response_text) {
                await sendGroupMessage(sock, remoteJid, decision.response_text, sender);
            }

        } catch (error) {
            if (error.code === 'ECONNREFUSED') {
                console.error('❌ AI serverinə qoşulmaq mümkün olmadı! Python serverinin işlədiyinə əmin olun!');
            } else {
                console.error('❌ AI ilə əlaqə xətası:', error.message);
            }
        }
    });

    sock.ev.on('creds.update', saveCreds);
}

// İşə sal
connectToWhatsApp().catch(err => {
    console.error('❌ Kritik xəta:', err);
    process.exit(1);
});

// Sessiyanı saxlamaq üçün
process.on('SIGINT', function() {
    console.log('\n👋 Bot dayandırılır...');
    process.exit();
});