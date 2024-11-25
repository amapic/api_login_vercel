import { VercelRequest, VercelResponse } from '@vercel/node';
// import loginHandler from './routes/login';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Ajouter les headers CORS
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,OPTIONS,PATCH,DELETE,POST,PUT'
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Gérer les requêtes OPTIONS (pre-flight)
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Router les requêtes vers les bons handlers
  const path = req.url?.split('/').filter(Boolean)[0];

  try {
    switch (path) {
      case 'login':
        return await loginHandler(req, res);
      
      default:
        return res.status(404).json({ message: 'Route non trouvée' });
    }
  } catch (error) {
    console.error('Erreur serveur:', error);
    return res.status(500).json({ message: 'Erreur interne du serveur' });
  }
}

// import { VercelRequest, VercelResponse } from '@vercel/node';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// En production, utilisez les variables d'environnement de Vercel
const HASHED_PASSWORD = process.env.HASHED_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

export async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  // Vérifier si c'est une requête POST
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Méthode non autorisée' });
  }

  try {
    const { password } = req.body;

    // Vérifier que le mot de passe est fourni
    if (!password) {
      return res.status(400).json({ message: 'Le mot de passe est requis' });
    }

    // Vérifier le mot de passe
    const isPasswordValid = await bcrypt.compare(password, HASHED_PASSWORD);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Mot de passe incorrect' });
    }

    // Créer le token JWT
    const token = jwt.sign(
      { authenticated: true },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Configuration du cookie
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 heures
      path: '/'
    };

    // Définir le cookie
    res.setHeader('Set-Cookie', `auth_token=${token}; ${Object.entries(cookieOptions)
      .map(([key, value]) => `${key}=${value}`)
      .join('; ')}`);

    return res.status(200).json({ message: 'Connexion réussie' });
  } catch (error) {
    console.error('Erreur de connexion:', error);
    return res.status(500).json({ message: 'Erreur interne du serveur' });
  }
}