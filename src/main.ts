import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: 'http://localhost:5173', // your Vite frontend
    credentials: true, // for cookies (refresh token)
  });

  app.setGlobalPrefix('api'); // using /api routes
  await app.listen(5000);
}
bootstrap();
