import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: 'http://localhost:5173', // or your frontend domain
    credentials: true, // allow cookies + auth headers
  });

  await app.listen(process.env.PORT || 5000);
}
bootstrap();
