// DOM Elementlerini Seçme
const plaintextEl = document.getElementById('plaintext');
const passwordEl = document.getElementById('password');
const encryptBtn = document.getElementById('encryptBtn');
const encryptedEl = document.getElementById('encrypted');
const copyEncrypted = document.getElementById('copyEncrypted');
const decryptBtn = document.getElementById('decryptBtn');
const decryptedEl = document.getElementById('decrypted');
const pasteEncrypted = document.getElementById('pasteEncrypted');
const messageArea = document.getElementById('messageArea');

// Kullanıcı Arayüzü Mesajlarını Gösterme Fonksiyonu
function showMessage(text, type = 'info') {
    messageArea.textContent = text;
    messageArea.className = `muted small ${type}`;
    // Hata dışındaki mesajları 5 saniye sonra temizle
    if (type !== 'error') {
        setTimeout(() => { messageArea.textContent = ''; messageArea.className = 'muted small'; }, 5000);
    }
}

// Yardımcı: string <-> ArrayBuffer
function str2ab(str) {
  return new TextEncoder().encode(str);
}
function ab2str(buf) {
  return new TextDecoder().decode(buf);
}
function buf2b64(buf) {
  let binary = '';
  let bytes = new Uint8Array(buf);
  // btoa/atob ikili veriyi hızlı işler, büyük veride sorun çıkmasını önlemek için döngü korunmuştur
  const chunk = 8192; 
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}
function b642ab(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// Anahtar türetme: PBKDF2
async function deriveKey(password, salt) {
  const pwKey = await crypto.subtle.importKey(
    'raw', str2ab(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  // İterasyon sayısı (150000) güncel güvenlik standartlarına uygundur
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 150000, hash: 'SHA-256' },
    pwKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Şifrele: çıktıda salt(16) + iv(12) + ciphertext
async function encryptMessage(plaintext, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, str2ab(plaintext));
  
  // ArrayBuffer'ları tek bir Uint8Array'de birleştir
  const combined = new Uint8Array(salt.byteLength + iv.byteLength + ct.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.byteLength);
  combined.set(new Uint8Array(ct), salt.byteLength + iv.byteLength);
  
  return buf2b64(combined.buffer);
}

// Çöz: base64 -> ayrıştır -> deriveKey -> decrypt
async function decryptMessage(b64, password) {
  try {
    const ab = b642ab(b64);
    const all = new Uint8Array(ab);
    // En az 16 (salt) + 12 (iv) + 1 (minimum ct) = 29 bayt olmalı
    if (all.length < 29) throw new Error('Geçersiz şifreli veri formatı.');
    
    const salt = all.slice(0, 16);
    const iv = all.slice(16, 28);
    const ct = all.slice(28);
    
    const key = await deriveKey(password, salt.buffer);
    const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
    
    return ab2str(ptBuf);
  } catch (e) {
    // Parola yanlışsa veya veri bozuksa bu hata fırlatılır
    console.error(e);
    throw new Error('Çözüm başarısız: Yanlış parola veya bozuk şifreli metin.');
  }
}

// --- Olay Dinleyicileri (Event Listeners) ---

encryptBtn.addEventListener('click', async () => {
  const pt = plaintextEl.value.trim();
  const pw = passwordEl.value;

  // Hata Düzeltme: Parola kontrolü zorunlu hale getirildi.
  if (!pw) {
    showMessage('🔒 Şifreleme/Çözme için bir parola girilmesi zorunludur.', 'error');
    return;
  }
  if (!pt) {
    showMessage('Mesaj boş olamaz.', 'error');
    return;
  }

  encryptBtn.disabled = true;
  showMessage('Şifreleniyor...', 'info');
  decryptedEl.value = ''; // Çözülen metni temizle
  
  try {
    const b64 = await encryptMessage(pt, pw);
    encryptedEl.value = b64;
    showMessage('✅ Mesaj başarıyla şifrelendi. Kopyalayabilirsiniz.', 'success');
  } catch (e) {
    showMessage('❌ Şifreleme hatası: ' + e.message, 'error');
  } finally {
    encryptBtn.disabled = false;
  }
});

copyEncrypted.addEventListener('click', async () => {
  const txt = encryptedEl.value;
  if (!txt) {
    showMessage('Kopyalanacak şifreli metin yok.', 'error');
    return;
  }
  try {
    await navigator.clipboard.writeText(txt);
    showMessage('📋 Şifreli metin panoya kopyalandı.', 'success');
  } catch (e) {
    showMessage('❌ Kopyalama başarısız: Tarayıcı izni verilmedi.', 'error');
  }
});

pasteEncrypted.addEventListener('click', async () => {
  try {
    const txt = await navigator.clipboard.readText();
    encryptedEl.value = txt.trim();
    showMessage('✅ Panodan yapıştırıldı. Şimdi parolayı girip "Çöz" butonuna basın.', 'success');
  } catch (e) {
    showMessage('❌ Panodan okuma başarısız: Tarayıcı izni verilmedi.', 'error');
  }
});

decryptBtn.addEventListener('click', async () => {
  const b64 = encryptedEl.value.trim();
  const pw = passwordEl.value;

  // Hata Düzeltme: Parola kontrolü zorunlu hale getirildi.
  if (!pw) {
    showMessage('🔒 Şifreleme/Çözme için bir parola girilmesi zorunludur.', 'error');
    return;
  }
  if (!b64) {
    showMessage('Çözülecek şifreli metin boş.', 'error');
    return;
  }

  decryptBtn.disabled = true;
  showMessage('Çözümleniyor...', 'info');

  try {
    const pt = await decryptMessage(b64, pw);
    decryptedEl.value = pt;
    showMessage('🔓 Mesaj başarıyla çözüldü.', 'success');
  } catch (e) {
    showMessage(e.message, 'error');
    decryptedEl.value = '';
  } finally {
    decryptBtn.disabled = false;
  }
});
  
