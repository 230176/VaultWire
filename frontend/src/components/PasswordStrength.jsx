import React from 'react';

export function passwordChecks(password, confirmPassword = '') {
  return {
    minLength: password.length >= 8,
    lower: /[a-z]/.test(password),
    upper: /[A-Z]/.test(password),
    number: /\d/.test(password),
    special: /[^A-Za-z0-9]/.test(password),
    match: confirmPassword ? password === confirmPassword : true
  };
}

export function PasswordStrength({ password, confirmPassword }) {
  const checks = passwordChecks(password, confirmPassword);
  const list = [
    ['At least 8 characters', checks.minLength],
    ['Lowercase letter', checks.lower],
    ['Uppercase letter', checks.upper],
    ['Number', checks.number],
    ['Special character', checks.special],
    ['Passwords match', checks.match]
  ];
  const score = Object.values(checks).filter(Boolean).length;
  const label = score <= 3 ? 'Weak' : score <= 5 ? 'Medium' : 'Strong';
  return (
    <div className="card">
      <div><strong>Password strength:</strong> {label}</div>
      <ul className="checklist">
        {list.map(([name, ok]) => <li key={name} className={ok ? 'ok' : 'bad'}>{ok ? '✓' : '✗'} {name}</li>)}
      </ul>
    </div>
  );
}
