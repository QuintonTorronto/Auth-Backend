import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  app.enableCors({
    origin: 'http://localhost:5173', // your Vite frontend
    credentials: true, // for cookies (refresh token)
    allowedHeaders: ['Content-Type', 'Authorization'], // ensure Authorization is allowed
  });

  app.setGlobalPrefix('api'); // using /api routes
  await app.listen(5000);
}
bootstrap();
