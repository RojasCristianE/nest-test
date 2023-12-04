import { INestApplication, ValidationPipe } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import { AppModule } from "../src/app.module";
import { PrismaService } from "../src/prisma/prisma.service";
import * as pactum from "pactum";
import { AuthDto } from "../src/auth/dto";

describe("App e2e", () => {
  let 
    app: INestApplication,
    prisma: PrismaService;

  beforeAll( async () => {
    const 
      moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile(),
      validations = { whitelist: true};

    app = moduleRef.createNestApplication();
    app.useGlobalPipes( new ValidationPipe( validations ) );

    await app.init();
    await app.listen(3333);

    prisma = app.get(PrismaService);

    await prisma.deleteData();

    pactum.request.setBaseUrl("http://localhost:3333");
  });

  afterAll( async () => { app.close() } );

  describe("Auth", () => {
    const dto: AuthDto = { email: "test@example.com", password: "12345678" };
    
    describe("SignUp", () => {
      it("should throw if email empty", () => pactum.spec().post("/auth/signup").withBody({ ...dto, email: "" }).expectStatus(400));
      it("should throw if password empty", () => pactum.spec().post("/auth/signup").withBody({ ...dto, password: "" }).expectStatus(400));
      it("should throw if no body", () => pactum.spec().post("/auth/signup").withBody({}).expectStatus(400));
      it("should signup", () => pactum.spec().post("/auth/signup").withBody(dto).expectStatus(201));
    });

    describe("Login", () => {
      it("should throw if email empty", () => pactum.spec().post("/auth/login").withBody({ ...dto, email: "" }).expectStatus(400));
      it("should throw if password empty", () => pactum.spec().post("/auth/login").withBody({ ...dto, password: "" }).expectStatus(400));
      it("should throw if no body", () => pactum.spec().post("/auth/login").withBody({}).expectStatus(400));
      it("should login", () => pactum.spec().post("/auth/login").withBody(dto).expectStatus(200).stores("user", "token"));
    });
  });

  describe("Users", () => {
    describe("Me", () => {
      it("should show user info", () => pactum.spec().get("/users/me").withBearerToken("$S{user}").expectStatus(200));
    });
    describe("All", () => {
      it("should list all users", () => pactum.spec().get("/users").withBearerToken("$S{user}").expectStatus(200));
    })
  });

  describe("Bookmark", () => {});
})