const request = require('supertest');
const faker = require('faker');
const httpStatus = require('http-status');
const httpMocks = require('node-mocks-http');
const moment = require('moment');
const bcrypt = require('bcryptjs');
const app = require('../../src/app');
const config = require('../../src/config/config');
const auth = require('../../src/middlewares/auth');
const { tokenService, idService } = require('../../src/services');
const ApiError = require('../../src/utils/ApiError');
const setupTestDB = require('../utils/setupTestDB');
const { Machine, Token } = require('../../src/models');
const { roleRights } = require('../../src/config/roles');
const { tokenTypes } = require('../../src/config/tokens');
const { machineOne, admin, insertMachines } = require('../fixtures/machine.fixture');
const { machineOneAccessToken, adminAccessToken } = require('../fixtures/token.fixture');

setupTestDB();

describe('Auth routes', () => {
  describe('POST /v1/auth/register', () => {
    let newMachine;
    beforeEach(() => {
      newMachine = {
        name: faker.name.findName(),
        id: faker.internet.id().toLowerCase(),
        password: 'password1',
      };
    });

    test('should return 201 and successfully register machine if request data is ok', async () => {
      const res = await request(app).post('/v1/auth/register').send(newMachine).expect(httpStatus.CREATED);

      expect(res.body.machine).not.toHaveProperty('password');
      expect(res.body.machine).toEqual({
        id: expect.anything(),
        name: newMachine.name,
        id: newMachine.id,
        role: 'machine',
        isIdVerified: false,
      });

      const dbMachine = await Machine.findById(res.body.machine.id);
      expect(dbMachine).toBeDefined();
      expect(dbMachine.password).not.toBe(newMachine.password);
      expect(dbMachine).toMatchObject({ name: newMachine.name, id: newMachine.id, role: 'machine', isIdVerified: false });

      expect(res.body.tokens).toEqual({
        access: { token: expect.anything(), expires: expect.anything() },
        refresh: { token: expect.anything(), expires: expect.anything() },
      });
    });

    test('should return 400 error if id is invalid', async () => {
      newMachine.id = 'invalidId';

      await request(app).post('/v1/auth/register').send(newMachine).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if id is already used', async () => {
      await insertMachines([machineOne]);
      newMachine.id = machineOne.id;

      await request(app).post('/v1/auth/register').send(newMachine).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password length is less than 8 characters', async () => {
      newMachine.password = 'passwo1';

      await request(app).post('/v1/auth/register').send(newMachine).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password does not contain both letters and numbers', async () => {
      newMachine.password = 'password';

      await request(app).post('/v1/auth/register').send(newMachine).expect(httpStatus.BAD_REQUEST);

      newMachine.password = '11111111';

      await request(app).post('/v1/auth/register').send(newMachine).expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('POST /v1/auth/login', () => {
    test('should return 200 and login machine if id and password match', async () => {
      await insertMachines([machineOne]);
      const loginCredentials = {
        id: machineOne.id,
        password: machineOne.password,
      };

      const res = await request(app).post('/v1/auth/login').send(loginCredentials).expect(httpStatus.OK);

      expect(res.body.machine).toEqual({
        id: expect.anything(),
        name: machineOne.name,
        id: machineOne.id,
        role: machineOne.role,
        isIdVerified: machineOne.isIdVerified,
      });

      expect(res.body.tokens).toEqual({
        access: { token: expect.anything(), expires: expect.anything() },
        refresh: { token: expect.anything(), expires: expect.anything() },
      });
    });

    test('should return 401 error if there are no machines with that id', async () => {
      const loginCredentials = {
        id: machineOne.id,
        password: machineOne.password,
      };

      const res = await request(app).post('/v1/auth/login').send(loginCredentials).expect(httpStatus.UNAUTHORIZED);

      expect(res.body).toEqual({ code: httpStatus.UNAUTHORIZED, message: 'Incorrect id or password' });
    });

    test('should return 401 error if password is wrong', async () => {
      await insertMachines([machineOne]);
      const loginCredentials = {
        id: machineOne.id,
        password: 'wrongPassword1',
      };

      const res = await request(app).post('/v1/auth/login').send(loginCredentials).expect(httpStatus.UNAUTHORIZED);

      expect(res.body).toEqual({ code: httpStatus.UNAUTHORIZED, message: 'Incorrect id or password' });
    });
  });

  describe('POST /v1/auth/logout', () => {
    test('should return 204 if refresh token is valid', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, machineOne._id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/logout').send({ refreshToken }).expect(httpStatus.NO_CONTENT);

      const dbRefreshTokenDoc = await Token.findOne({ token: refreshToken });
      expect(dbRefreshTokenDoc).toBe(null);
    });

    test('should return 400 error if refresh token is missing from request body', async () => {
      await request(app).post('/v1/auth/logout').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 error if refresh token is not found in the database', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/logout').send({ refreshToken }).expect(httpStatus.NOT_FOUND);
    });

    test('should return 404 error if refresh token is blacklisted', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, machineOne._id, expires, tokenTypes.REFRESH, true);

      await request(app).post('/v1/auth/logout').send({ refreshToken }).expect(httpStatus.NOT_FOUND);
    });
  });

  describe('POST /v1/auth/refresh-tokens', () => {
    test('should return 200 and new auth tokens if refresh token is valid', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, machineOne._id, expires, tokenTypes.REFRESH);

      const res = await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.OK);

      expect(res.body).toEqual({
        access: { token: expect.anything(), expires: expect.anything() },
        refresh: { token: expect.anything(), expires: expect.anything() },
      });

      const dbRefreshTokenDoc = await Token.findOne({ token: res.body.refresh.token });
      expect(dbRefreshTokenDoc).toMatchObject({ type: tokenTypes.REFRESH, machine: machineOne._id, blacklisted: false });

      const dbRefreshTokenCount = await Token.countDocuments();
      expect(dbRefreshTokenCount).toBe(1);
    });

    test('should return 400 error if refresh token is missing from request body', async () => {
      await request(app).post('/v1/auth/refresh-tokens').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 error if refresh token is signed using an invalid secret', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.REFRESH, 'invalidSecret');
      await tokenService.saveToken(refreshToken, machineOne._id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is not found in the database', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is blacklisted', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, machineOne._id, expires, tokenTypes.REFRESH, true);

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if refresh token is expired', async () => {
      await insertMachines([machineOne]);
      const expires = moment().subtract(1, 'minutes');
      const refreshToken = tokenService.generateToken(machineOne._id, expires);
      await tokenService.saveToken(refreshToken, machineOne._id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 error if machine is not found', async () => {
      const expires = moment().add(config.jwt.refreshExpirationDays, 'days');
      const refreshToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.REFRESH);
      await tokenService.saveToken(refreshToken, machineOne._id, expires, tokenTypes.REFRESH);

      await request(app).post('/v1/auth/refresh-tokens').send({ refreshToken }).expect(httpStatus.UNAUTHORIZED);
    });
  });

  describe('POST /v1/auth/forgot-password', () => {
    beforeEach(() => {
      jest.spyOn(idService.transport, 'sendMail').mockResolvedValue();
    });

    test('should return 204 and send reset password id to the machine', async () => {
      await insertMachines([machineOne]);
      const sendResetPasswordIdSpy = jest.spyOn(idService, 'sendResetPasswordId');

      await request(app).post('/v1/auth/forgot-password').send({ id: machineOne.id }).expect(httpStatus.NO_CONTENT);

      expect(sendResetPasswordIdSpy).toHaveBeenCalledWith(machineOne.id, expect.any(String));
      const resetPasswordToken = sendResetPasswordIdSpy.mock.calls[0][1];
      const dbResetPasswordTokenDoc = await Token.findOne({ token: resetPasswordToken, machine: machineOne._id });
      expect(dbResetPasswordTokenDoc).toBeDefined();
    });

    test('should return 400 if id is missing', async () => {
      await insertMachines([machineOne]);

      await request(app).post('/v1/auth/forgot-password').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 if id does not belong to any machine', async () => {
      await request(app).post('/v1/auth/forgot-password').send({ id: machineOne.id }).expect(httpStatus.NOT_FOUND);
    });
  });

  describe('POST /v1/auth/reset-password', () => {
    test('should return 204 and reset the password', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, machineOne._id, expires, tokenTypes.RESET_PASSWORD);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.NO_CONTENT);

      const dbMachine = await Machine.findById(machineOne._id);
      const isPasswordMatch = await bcrypt.compare('password2', dbMachine.password);
      expect(isPasswordMatch).toBe(true);

      const dbResetPasswordTokenCount = await Token.countDocuments({ machine: machineOne._id, type: tokenTypes.RESET_PASSWORD });
      expect(dbResetPasswordTokenCount).toBe(0);
    });

    test('should return 400 if reset password token is missing', async () => {
      await insertMachines([machineOne]);

      await request(app).post('/v1/auth/reset-password').send({ password: 'password2' }).expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 if reset password token is blacklisted', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, machineOne._id, expires, tokenTypes.RESET_PASSWORD, true);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if reset password token is expired', async () => {
      await insertMachines([machineOne]);
      const expires = moment().subtract(1, 'minutes');
      const resetPasswordToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, machineOne._id, expires, tokenTypes.RESET_PASSWORD);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if machine is not found', async () => {
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, machineOne._id, expires, tokenTypes.RESET_PASSWORD);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password2' })
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 400 if password is missing or invalid', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
      const resetPasswordToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.RESET_PASSWORD);
      await tokenService.saveToken(resetPasswordToken, machineOne._id, expires, tokenTypes.RESET_PASSWORD);

      await request(app).post('/v1/auth/reset-password').query({ token: resetPasswordToken }).expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'short1' })
        .expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: 'password' })
        .expect(httpStatus.BAD_REQUEST);

      await request(app)
        .post('/v1/auth/reset-password')
        .query({ token: resetPasswordToken })
        .send({ password: '11111111' })
        .expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('POST /v1/auth/send-verification-id', () => {
    beforeEach(() => {
      jest.spyOn(idService.transport, 'sendMail').mockResolvedValue();
    });

    test('should return 204 and send verification id to the machine', async () => {
      await insertMachines([machineOne]);
      const sendVerificationIdSpy = jest.spyOn(idService, 'sendVerificationId');

      await request(app)
        .post('/v1/auth/send-verification-id')
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .expect(httpStatus.NO_CONTENT);

      expect(sendVerificationIdSpy).toHaveBeenCalledWith(machineOne.id, expect.any(String));
      const verifyIdToken = sendVerificationIdSpy.mock.calls[0][1];
      const dbVerifyIdToken = await Token.findOne({ token: verifyIdToken, machine: machineOne._id });

      expect(dbVerifyIdToken).toBeDefined();
    });

    test('should return 401 error if access token is missing', async () => {
      await insertMachines([machineOne]);

      await request(app).post('/v1/auth/send-verification-id').send().expect(httpStatus.UNAUTHORIZED);
    });
  });

  describe('POST /v1/auth/verify-id', () => {
    test('should return 204 and verify the id', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.verifyIdExpirationMinutes, 'minutes');
      const verifyIdToken = tokenService.generateToken(machineOne._id, expires);
      await tokenService.saveToken(verifyIdToken, machineOne._id, expires, tokenTypes.VERIFY_EMAIL);

      await request(app)
        .post('/v1/auth/verify-id')
        .query({ token: verifyIdToken })
        .send()
        .expect(httpStatus.NO_CONTENT);

      const dbMachine = await Machine.findById(machineOne._id);

      expect(dbMachine.isIdVerified).toBe(true);

      const dbVerifyIdToken = await Token.countDocuments({
        machine: machineOne._id,
        type: tokenTypes.VERIFY_EMAIL,
      });
      expect(dbVerifyIdToken).toBe(0);
    });

    test('should return 400 if verify id token is missing', async () => {
      await insertMachines([machineOne]);

      await request(app).post('/v1/auth/verify-id').send().expect(httpStatus.BAD_REQUEST);
    });

    test('should return 401 if verify id token is blacklisted', async () => {
      await insertMachines([machineOne]);
      const expires = moment().add(config.jwt.verifyIdExpirationMinutes, 'minutes');
      const verifyIdToken = tokenService.generateToken(machineOne._id, expires);
      await tokenService.saveToken(verifyIdToken, machineOne._id, expires, tokenTypes.VERIFY_EMAIL, true);

      await request(app)
        .post('/v1/auth/verify-id')
        .query({ token: verifyIdToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if verify id token is expired', async () => {
      await insertMachines([machineOne]);
      const expires = moment().subtract(1, 'minutes');
      const verifyIdToken = tokenService.generateToken(machineOne._id, expires);
      await tokenService.saveToken(verifyIdToken, machineOne._id, expires, tokenTypes.VERIFY_EMAIL);

      await request(app)
        .post('/v1/auth/verify-id')
        .query({ token: verifyIdToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 401 if machine is not found', async () => {
      const expires = moment().add(config.jwt.verifyIdExpirationMinutes, 'minutes');
      const verifyIdToken = tokenService.generateToken(machineOne._id, expires);
      await tokenService.saveToken(verifyIdToken, machineOne._id, expires, tokenTypes.VERIFY_EMAIL);

      await request(app)
        .post('/v1/auth/verify-id')
        .query({ token: verifyIdToken })
        .send()
        .expect(httpStatus.UNAUTHORIZED);
    });
  });
});

describe('Auth middleware', () => {
  test('should call next with no errors if access token is valid', async () => {
    await insertMachines([machineOne]);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${machineOneAccessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
    expect(req.machine._id).toEqual(machineOne._id);
  });

  test('should call next with unauthorized error if access token is not found in header', async () => {
    await insertMachines([machineOne]);
    const req = httpMocks.createRequest();
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with unauthorized error if access token is not a valid jwt token', async () => {
    await insertMachines([machineOne]);
    const req = httpMocks.createRequest({ headers: { Authorization: 'Bearer randomToken' } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with unauthorized error if the token is not an access token', async () => {
    await insertMachines([machineOne]);
    const expires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');
    const refreshToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.REFRESH);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${refreshToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with unauthorized error if access token is generated with an invalid secret', async () => {
    await insertMachines([machineOne]);
    const expires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');
    const accessToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.ACCESS, 'invalidSecret');
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${accessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with unauthorized error if access token is expired', async () => {
    await insertMachines([machineOne]);
    const expires = moment().subtract(1, 'minutes');
    const accessToken = tokenService.generateToken(machineOne._id, expires, tokenTypes.ACCESS);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${accessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with unauthorized error if machine is not found', async () => {
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${machineOneAccessToken}` } });
    const next = jest.fn();

    await auth()(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: httpStatus.UNAUTHORIZED, message: 'Please authenticate' })
    );
  });

  test('should call next with forbidden error if machine does not have required rights and id is not in params', async () => {
    await insertMachines([machineOne]);
    const req = httpMocks.createRequest({ headers: { Authorization: `Bearer ${machineOneAccessToken}` } });
    const next = jest.fn();

    await auth('anyRight')(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ statusCode: httpStatus.FORBIDDEN, message: 'Forbidden' }));
  });

  test('should call next with no errors if machine does not have required rights but id is in params', async () => {
    await insertMachines([machineOne]);
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${machineOneAccessToken}` },
      params: { id: machineOne._id.toHexString() },
    });
    const next = jest.fn();

    await auth('anyRight')(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
  });

  test('should call next with no errors if machine has required rights', async () => {
    await insertMachines([admin]);
    const req = httpMocks.createRequest({
      headers: { Authorization: `Bearer ${adminAccessToken}` },
      params: { id: machineOne._id.toHexString() },
    });
    const next = jest.fn();

    await auth(...roleRights.get('admin'))(req, httpMocks.createResponse(), next);

    expect(next).toHaveBeenCalledWith();
  });
});
