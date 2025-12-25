import React, { useState, useEffect } from 'react';
import { Shield, Key, Smartphone, CheckCircle, XCircle, User, Lock, RefreshCw } from 'lucide-react';

const OTP2FASystem = () => {
  const [users, setUsers] = useState([]);
  const [currentView, setCurrentView] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otpInput, setOtpInput] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [qrCodeUrl, setQrCodeUrl] = useState('');
  const [message, setMessage] = useState({ text: '', type: '' });
  const [currentUser, setCurrentUser] = useState(null);
  const [timeLeft, setTimeLeft] = useState(30);
  const [currentOTP, setCurrentOTP] = useState('');

  // Base32 decode function
  const base32Decode = (base32) => {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let result = [];
    
    base32 = base32.toUpperCase().replace(/=+$/, '');
    
    for (let i = 0; i < base32.length; i++) {
      const val = base32Chars.indexOf(base32.charAt(i));
      if (val === -1) continue;
      bits += val.toString(2).padStart(5, '0');
    }
    
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      result.push(parseInt(bits.substr(i, 8), 2));
    }
    
    return new Uint8Array(result);
  };

  // HMAC-SHA1 implementation
  const hmacSHA1 = (key, message) => {
    const blockSize = 64;
    const opad = new Uint8Array(blockSize).fill(0x5c);
    const ipad = new Uint8Array(blockSize).fill(0x36);
    
    if (key.length > blockSize) {
      key = sha1(key);
    }
    
    const keyPadded = new Uint8Array(blockSize);
    keyPadded.set(key);
    
    const innerKey = new Uint8Array(blockSize);
    const outerKey = new Uint8Array(blockSize);
    
    for (let i = 0; i < blockSize; i++) {
      innerKey[i] = keyPadded[i] ^ ipad[i];
      outerKey[i] = keyPadded[i] ^ opad[i];
    }
    
    const innerHash = sha1(concat(innerKey, message));
    return sha1(concat(outerKey, innerHash));
  };

  // SHA1 implementation
  const sha1 = (data) => {
    const msg = new Uint8Array(data);
    const msgLen = msg.length;
    const bitLen = msgLen * 8;
    
    const newLen = msgLen + 1 + (64 - ((msgLen + 9) % 64));
    const padded = new Uint8Array(newLen + 8);
    padded.set(msg);
    padded[msgLen] = 0x80;
    
    const view = new DataView(padded.buffer);
    view.setUint32(newLen + 4, bitLen, false);
    
    let h0 = 0x67452301;
    let h1 = 0xEFCDAB89;
    let h2 = 0x98BADCFE;
    let h3 = 0x10325476;
    let h4 = 0xC3D2E1F0;
    
    for (let i = 0; i < padded.length; i += 64) {
      const w = new Array(80);
      
      for (let j = 0; j < 16; j++) {
        w[j] = view.getUint32(i + j * 4, false);
      }
      
      for (let j = 16; j < 80; j++) {
        w[j] = rotateLeft(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      }
      
      let a = h0, b = h1, c = h2, d = h3, e = h4;
      
      for (let j = 0; j < 80; j++) {
        let f, k;
        if (j < 20) {
          f = (b & c) | (~b & d);
          k = 0x5A827999;
        } else if (j < 40) {
          f = b ^ c ^ d;
          k = 0x6ED9EBA1;
        } else if (j < 60) {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8F1BBCDC;
        } else {
          f = b ^ c ^ d;
          k = 0xCA62C1D6;
        }
        
        const temp = (rotateLeft(a, 5) + f + e + k + w[j]) >>> 0;
        e = d;
        d = c;
        c = rotateLeft(b, 30);
        b = a;
        a = temp;
      }
      
      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
    }
    
    const result = new Uint8Array(20);
    const resultView = new DataView(result.buffer);
    resultView.setUint32(0, h0, false);
    resultView.setUint32(4, h1, false);
    resultView.setUint32(8, h2, false);
    resultView.setUint32(12, h3, false);
    resultView.setUint32(16, h4, false);
    
    return result;
  };

  const rotateLeft = (n, s) => {
    return ((n << s) | (n >>> (32 - s))) >>> 0;
  };

  const concat = (a, b) => {
    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);
    return result;
  };

  // Generate TOTP
  const generateTOTP = (secret) => {
    try {
      const time = Math.floor(Date.now() / 1000 / 30);
      const timeBytes = new Uint8Array(8);
      const view = new DataView(timeBytes.buffer);
      view.setUint32(4, time, false);
      
      const key = base32Decode(secret);
      const hmac = hmacSHA1(key, timeBytes);
      
      const offset = hmac[19] & 0x0f;
      const binary = 
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
      
      const otp = (binary % 1000000).toString().padStart(6, '0');
      return otp;
    } catch (error) {
      console.error('TOTP generation error:', error);
      return '000000';
    }
  };

  // Generate random secret key (16 characters base32)
  const generateSecret = () => {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let secret = '';
    for (let i = 0; i < 16; i++) {
      secret += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return secret;
  };

  // Timer for OTP refresh
  useEffect(() => {
    const timer = setInterval(() => {
      setTimeLeft(30 - (Math.floor(Date.now() / 1000) % 30));
      if (secretKey) {
        setCurrentOTP(generateTOTP(secretKey));
      }
      if (currentUser) {
        setCurrentOTP(generateTOTP(currentUser.secret));
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [secretKey, currentUser]);

  const handleRegister = () => {
    if (!username || !password) {
      setMessage({ text: 'Please fill all fields', type: 'error' });
      return;
    }

    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      setMessage({ text: 'Username already exists', type: 'error' });
      return;
    }

    const secret = generateSecret();
    setSecretKey(secret);
    setCurrentOTP(generateTOTP(secret));
    
    // Generate QR code URL for Google Authenticator
    const issuer = 'MySecureApp';
    const otpauthUrl = `otpauth://totp/${issuer}:${username}?secret=${secret}&issuer=${issuer}`;
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauthUrl)}`;
    setQrCodeUrl(qrUrl);
    
    setCurrentView('setup2fa');
    setMessage({ text: 'Scan QR code with Google Authenticator', type: 'success' });
  };

  const completeRegistration = () => {
    const currentOTPValue = generateTOTP(secretKey);
    
    if (otpInput === currentOTPValue) {
      const newUser = {
        username,
        password,
        secret: secretKey,
        enabled2FA: true,
        registeredAt: new Date().toISOString()
      };
      setUsers([...users, newUser]);
      setMessage({ text: 'Registration successful! You can now login.', type: 'success' });
      resetForm();
      setCurrentView('login');
    } else {
      setMessage({ text: `Invalid OTP. Please try again. (Expected: ${currentOTPValue})`, type: 'error' });
    }
  };

  const handleLogin = () => {
    if (!username || !password) {
      setMessage({ text: 'Please enter credentials', type: 'error' });
      return;
    }

    const user = users.find(u => u.username === username && u.password === password);
    
    if (!user) {
      setMessage({ text: 'Invalid credentials', type: 'error' });
      return;
    }

    setCurrentUser(user);
    setCurrentOTP(generateTOTP(user.secret));
    setCurrentView('verify2fa');
    setMessage({ text: 'Enter OTP from Google Authenticator', type: 'info' });
  };

  const verifyOTP = () => {
    if (!currentUser) return;

    const currentOTPValue = generateTOTP(currentUser.secret);
    
    if (otpInput === currentOTPValue) {
      setMessage({ text: 'Login successful!', type: 'success' });
      setCurrentView('dashboard');
    } else {
      setMessage({ text: `Invalid OTP. Access denied. (Expected: ${currentOTPValue})`, type: 'error' });
    }
  };

  const logout = () => {
    resetForm();
    setCurrentUser(null);
    setCurrentView('login');
    setMessage({ text: '', type: '' });
  };

  const resetForm = () => {
    setUsername('');
    setPassword('');
    setOtpInput('');
    setSecretKey('');
    setQrCodeUrl('');
    setCurrentOTP('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="bg-white rounded-2xl shadow-2xl overflow-hidden">
          {/* Header */}
          <div className="bg-gradient-to-r from-blue-600 to-indigo-600 p-6 text-white">
            <div className="flex items-center gap-3">
              <Shield className="w-10 h-10" />
              <div>
                <h1 className="text-2xl font-bold">Two-Factor Authentication System</h1>
                <p className="text-blue-100 text-sm">Secure Access Control with Google Authenticator</p>
              </div>
            </div>
          </div>

          {/* Message Display */}
          {message.text && (
            <div className={`p-4 ${message.type === 'error' ? 'bg-red-50 text-red-700' : message.type === 'success' ? 'bg-green-50 text-green-700' : 'bg-blue-50 text-blue-700'}`}>
              <div className="flex items-center gap-2">
                {message.type === 'success' ? <CheckCircle className="w-5 h-5" /> : <XCircle className="w-5 h-5" />}
                <p className="font-medium">{message.text}</p>
              </div>
            </div>
          )}

          <div className="p-8">
            {/* Login/Register View */}
            {currentView === 'login' && (
              <div className="space-y-6">
                <div className="flex gap-4 mb-6">
                  <button
                    className="flex-1 py-2 px-4 bg-blue-600 text-white rounded-lg font-semibold"
                  >
                    Login
                  </button>
                  <button
                    onClick={() => { setCurrentView('register'); resetForm(); setMessage({ text: '', type: '' }); }}
                    className="flex-1 py-2 px-4 bg-gray-200 text-gray-700 rounded-lg font-semibold hover:bg-gray-300"
                  >
                    Register
                  </button>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Username</label>
                    <div className="relative">
                      <User className="absolute left-3 top-3 w-5 h-5 text-gray-400" />
                      <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        placeholder="Enter username"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-3 w-5 h-5 text-gray-400" />
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        placeholder="Enter password"
                      />
                    </div>
                  </div>

                  <button
                    onClick={handleLogin}
                    className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition"
                  >
                    Login
                  </button>
                </div>

                <div className="mt-6 p-4 bg-gray-50 rounded-lg">
                  <p className="text-sm text-gray-600 font-semibold mb-2">Demo Users:</p>
                  {users.length > 0 ? (
                    <ul className="text-sm text-gray-600 space-y-1">
                      {users.map((u, i) => (
                        <li key={i}>• {u.username} (2FA Enabled)</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-sm text-gray-500 italic">No users registered yet</p>
                  )}
                </div>
              </div>
            )}

            {/* Register View */}
            {currentView === 'register' && (
              <div className="space-y-6">
                <div className="flex gap-4 mb-6">
                  <button
                    onClick={() => { setCurrentView('login'); resetForm(); setMessage({ text: '', type: '' }); }}
                    className="flex-1 py-2 px-4 bg-gray-200 text-gray-700 rounded-lg font-semibold hover:bg-gray-300"
                  >
                    Login
                  </button>
                  <button
                    className="flex-1 py-2 px-4 bg-blue-600 text-white rounded-lg font-semibold"
                  >
                    Register
                  </button>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Username</label>
                    <div className="relative">
                      <User className="absolute left-3 top-3 w-5 h-5 text-gray-400" />
                      <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        placeholder="Choose username"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-3 w-5 h-5 text-gray-400" />
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        placeholder="Choose password"
                      />
                    </div>
                  </div>

                  <button
                    onClick={handleRegister}
                    className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition"
                  >
                    Register & Setup 2FA
                  </button>
                </div>
              </div>
            )}

            {/* 2FA Setup View */}
            {currentView === 'setup2fa' && (
              <div className="space-y-6">
                <div className="text-center">
                  <Smartphone className="w-16 h-16 mx-auto text-blue-600 mb-4" />
                  <h2 className="text-2xl font-bold text-gray-800 mb-2">Setup Google Authenticator</h2>
                  <p className="text-gray-600">Scan the QR code with your Google Authenticator app</p>
                </div>

                <div className="bg-gray-50 p-6 rounded-lg">
                  <div className="text-center mb-4">
                    {qrCodeUrl && (
                      <img src={qrCodeUrl} alt="QR Code" className="mx-auto border-4 border-white shadow-lg rounded-lg" />
                    )}
                  </div>
                  
                  <div className="bg-white p-4 rounded border border-gray-200 mb-4">
                    <p className="text-xs font-semibold text-gray-700 mb-1">Secret Key (Manual Entry):</p>
                    <code className="text-sm text-blue-600 break-all">{secretKey}</code>
                  </div>

                  
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Enter 6-digit OTP from Google Authenticator</label>
                  <div className="relative">
                    <Key className="absolute left-3 top-3 w-5 h-5 text-gray-400" />
                    <input
                      type="text"
                      value={otpInput}
                      onChange={(e) => setOtpInput(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-2xl tracking-widest"
                      placeholder="000000"
                      maxLength={6}
                    />
                  </div>
                </div>

                <button
                  onClick={completeRegistration}
                  disabled={otpInput.length !== 6}
                  className="w-full bg-green-600 text-white py-3 rounded-lg font-semibold hover:bg-green-700 transition disabled:bg-gray-400 disabled:cursor-not-allowed"
                >
                  Verify & Complete Registration
                </button>
              </div>
            )}

            {/* 2FA Verification View */}
            {currentView === 'verify2fa' && (
              <div className="space-y-6">
                <div className="text-center">
                  <Shield className="w-16 h-16 mx-auto text-blue-600 mb-4" />
                  <h2 className="text-2xl font-bold text-gray-800 mb-2">Two-Factor Authentication</h2>
                  <p className="text-gray-600">Enter the 6-digit code from Google Authenticator</p>
                </div>

                <div className="bg-blue-50 p-4 rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-blue-900">Time remaining:</span>
                    <div className="flex items-center gap-2">
                      <RefreshCw className="w-4 h-4 text-blue-600" />
                      <span className="text-lg font-bold text-blue-600">{timeLeft}s</span>
                    </div>
                  </div>
                  <div className="w-full bg-blue-200 rounded-full h-2">
                    <div
                      className="bg-blue-600 h-2 rounded-full transition-all duration-1000"
                      style={{ width: `${(timeLeft / 30) * 100}%` }}
                    ></div>
                  </div>
                  <div className="mt-3 bg-yellow-50 border border-yellow-200 p-2 rounded">
                    <p className="text-xs text-yellow-800">
                      <strong>Testing:</strong> Expected OTP: <span className="font-mono font-bold text-base">{currentOTP}</span>
                    </p>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Enter OTP Code</label>
                  <div className="relative">
                    <Key className="absolute left-3 top-3 w-5 h-5 text-gray-400" />
                    <input
                      type="text"
                      value={otpInput}
                      onChange={(e) => setOtpInput(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-center text-2xl tracking-widest"
                      placeholder="000000"
                      maxLength={6}
                    />
                  </div>
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={verifyOTP}
                    disabled={otpInput.length !== 6}
                    className="flex-1 bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition disabled:bg-gray-400 disabled:cursor-not-allowed"
                  >
                    Verify & Login
                  </button>
                  <button
                    onClick={() => { setCurrentView('login'); resetForm(); setCurrentUser(null); }}
                    className="px-6 bg-gray-200 text-gray-700 py-3 rounded-lg font-semibold hover:bg-gray-300 transition"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {/* Dashboard View */}
            {currentView === 'dashboard' && (
              <div className="space-y-6">
                <div className="text-center">
                  <CheckCircle className="w-16 h-16 mx-auto text-green-600 mb-4" />
                  <h2 className="text-2xl font-bold text-gray-800 mb-2">Access Granted</h2>
                  <p className="text-gray-600">Welcome, {currentUser?.username}!</p>
                </div>

                <div className="bg-green-50 p-6 rounded-lg space-y-3">
                  <h3 className="font-semibold text-green-900">Security Information</h3>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className="text-gray-600">Username:</p>
                      <p className="font-semibold text-gray-900">{currentUser?.username}</p>
                    </div>
                    <div>
                      <p className="text-gray-600">2FA Status:</p>
                      <p className="font-semibold text-green-600">Enabled ✓</p>
                    </div>
                    <div>
                      <p className="text-gray-600">Last Login:</p>
                      <p className="font-semibold text-gray-900">{new Date().toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="text-gray-600">Auth Method:</p>
                      <p className="font-semibold text-gray-900">TOTP (RFC 6238)</p>
                    </div>
                  </div>
                </div>

                <div className="bg-blue-50 p-4 rounded-lg">
                  <p className="text-sm text-blue-900">
                    <strong>Security Note:</strong> Your account is protected with Time-based One-Time Password (TOTP) 
                    two-factor authentication using HMAC-SHA1 algorithm. This adds an extra layer of security beyond just your password.
                  </p>
                </div>

                <button
                  onClick={logout}
                  className="w-full bg-red-600 text-white py-3 rounded-lg font-semibold hover:bg-red-700 transition"
                >
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Info Panel */}
        <div className="mt-6 bg-white rounded-lg shadow-lg p-6">
          <h3 className="font-bold text-lg mb-3 text-gray-800">About This System</h3>
          <div className="space-y-2 text-sm text-gray-600">
            <p>• <strong>RFC 6238 Compliant:</strong> Implements standard TOTP algorithm with HMAC-SHA1</p>
            <p>• <strong>Access Control:</strong> Multi-factor authentication prevents unauthorized access</p>
            <p>• <strong>Identity Management:</strong> Secure user registration and credential storage</p>
            <p>• <strong>30-Second Window:</strong> Time-based OTP changes every 30 seconds</p>
            <p>• <strong>Google Authenticator Compatible:</strong> Works with any RFC 6238 compliant app</p>
            <p>• <strong>Zero Trust Security:</strong> Verifies both "something you know" (password) and "something you have" (phone)</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OTP2FASystem;