import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  app.enableCors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173', // frontend origin
    credentials: true, // for cookies (refresh token)
    allowedHeaders: ['Content-Type', 'Authorization'], //ensures Authorization
  });

  app.setGlobalPrefix('api'); // using /api
  await app.listen(process.env.PORT || 5000);
}
bootstrap();
