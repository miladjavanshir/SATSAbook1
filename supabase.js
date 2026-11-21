'use strict';

// کلید Publishable عمومی است؛ هیچ Secret یا service_role در مرورگر قرار ندهید.
const SUPABASE_URL = 'https://qlpnwgiidmwykpabrxps.supabase.co';
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_OpgdWYA88oJtnTsfRZz0RA_Q3YGvVp7';
let supabaseClient = null;

function getSupabaseClient() {
  if (supabaseClient) return supabaseClient;
  if (!window.supabase || typeof window.supabase.createClient !== 'function') {
    throw Object.assign(new Error('Supabase client could not be loaded.'), { code: 'client_unavailable' });
  }
  supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
  });
  return supabaseClient;
}

function supabaseReturnUrl() {
  if (!/^https?:$/.test(window.location.protocol)) return undefined;
  const url = new URL(window.location.href);
  url.hash = '';
  url.search = '';
  return url.href;
}

// عکس کامل در جدول خصوصی app_profiles و کش محلی ذخیره می‌شود. فقط بندانگشتی کوچک در Auth metadata
// قرار می‌گیرد تا اندازهٔ JWT و سربرگ‌های درخواست با عکس چندمگابایتی خراب نشود.
async function supabasePhotoThumbnail(photo) {
  if (typeof photo !== 'string' || !photo) return '';
  if (!photo.startsWith('data:image/')) return /^https:\/\//.test(photo) && photo.length <= 2048 ? photo : '';
  try {
    const image = await new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = reject;
      img.src = photo;
    });
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) return '';
    for (const size of [96, 72, 48, 32]) {
      const scale = Math.min(1, size / Math.max(image.naturalWidth, image.naturalHeight));
      canvas.width = Math.max(1, Math.round(image.naturalWidth * scale));
      canvas.height = Math.max(1, Math.round(image.naturalHeight * scale));
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
      const thumbnail = canvas.toDataURL('image/jpeg', 0.4);
      if (thumbnail.length <= 2048) return thumbnail;
    }
  } catch (_) {}
  return '';
}

async function supabaseProfileMetadata(user) {
  const name = String(user.fullname || '').slice(0, 200);
  return {
    full_name: name,
    name: name,
    pageNumber: Number(user.pageNumber),
    photo: await supabasePhotoThumbnail(user.photo || '')
  };
}

async function supabaseRegister(user, password) {
  const options = { data: await supabaseProfileMetadata(user) };
  const redirect = supabaseReturnUrl();
  if (redirect) options.emailRedirectTo = redirect;
  const { data, error } = await getSupabaseClient().auth.signUp({
    email: String(user.email || '').trim().toLowerCase(),
    password,
    options
  });
  if (error) throw error;
  if (!data || !data.user) throw Object.assign(new Error('Registration did not return a user.'), { code: 'signup_failed' });
  if (Array.isArray(data.user.identities) && data.user.identities.length === 0) {
    throw Object.assign(new Error('This email is already registered.'), { code: 'user_already_exists' });
  }
  // نبودن session به معنی نیاز به تأیید ایمیل است، نه ورود موفق.
  return data;
}

async function supabaseLogin(email, password) {
  const { data, error } = await getSupabaseClient().auth.signInWithPassword({
    email: String(email || '').trim().toLowerCase(), password
  });
  if (error) throw error;
  if (!data || !data.user || !data.session || !data.session.access_token) {
    throw Object.assign(new Error('No authenticated session was returned.'), { code: 'session_missing' });
  }
  return data;
}

async function supabaseCurrentUser() {
  const client = getSupabaseClient();
  const { data: sessionData, error: sessionError } = await client.auth.getSession();
  if (sessionError) throw sessionError;
  if (!sessionData || !sessionData.session) return null;
  // فقط ایمیل ذخیره‌شده در IndexedDB یا یک JWT خوانده‌شده، سند ورود نیست.
  const { data, error } = await client.auth.getUser();
  if (error) throw error;
  return data && data.user ? data.user : null;
}

async function supabaseUpdateProfile(user, { email, password } = {}) {
  const attributes = { data: await supabaseProfileMetadata(user) };
  if (email && email !== user.email) attributes.email = email;
  if (password) attributes.password = password;
  const redirect = supabaseReturnUrl();
  const { data, error } = await getSupabaseClient().auth.updateUser(
    attributes, redirect ? { emailRedirectTo: redirect } : undefined
  );
  if (error) throw error;
  if (!data || !data.user) throw Object.assign(new Error('No updated user was returned.'), { code: 'session_missing' });
  return data.user;
}

async function supabaseLogout() {
  const { error } = await getSupabaseClient().auth.signOut({ scope: 'local' });
  if (error) throw error;
}
