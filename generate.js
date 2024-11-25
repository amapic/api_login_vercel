bcrypt=require('bcrypt');

const password = 'Refused2?';
bcrypt.hash(password, 10).then(hash => {
  console.log('Mot de passe hashé:', hash);
});