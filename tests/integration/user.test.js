const request = require('supertest');
const faker = require('faker');
const httpStatus = require('http-status');
const app = require('../../src/app');
const setupTestDB = require('../utils/setupTestDB');
const { Machine } = require('../../src/models');
const { machineOne, machineTwo, admin, insertMachines } = require('../fixtures/machine.fixture');
const { machineOneAccessToken, adminAccessToken } = require('../fixtures/token.fixture');

setupTestDB();

describe('Machine routes', () => {
  describe('POST /v1/machines', () => {
    let newMachine;

    beforeEach(() => {
      newMachine = {
        name: faker.name.findName(),
        id: faker.internet.id().toLowerCase(),
        password: 'password1',
        role: 'machine',
      };
    });

    test('should return 201 and successfully create new machine if data is ok', async () => {
      await insertMachines([admin]);

      const res = await request(app)
        .post('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newMachine)
        .expect(httpStatus.CREATED);

      expect(res.body).not.toHaveProperty('password');
      expect(res.body).toEqual({
        id: expect.anything(),
        name: newMachine.name,
        id: newMachine.id,
        role: newMachine.role,
        isIdVerified: false,
      });

      const dbMachine = await Machine.findById(res.body.id);
      expect(dbMachine).toBeDefined();
      expect(dbMachine.password).not.toBe(newMachine.password);
      expect(dbMachine).toMatchObject({ name: newMachine.name, id: newMachine.id, role: newMachine.role, isIdVerified: false });
    });

    test('should be able to create an admin as well', async () => {
      await insertMachines([admin]);
      newMachine.role = 'admin';

      const res = await request(app)
        .post('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newMachine)
        .expect(httpStatus.CREATED);

      expect(res.body.role).toBe('admin');

      const dbMachine = await Machine.findById(res.body.id);
      expect(dbMachine.role).toBe('admin');
    });

    test('should return 401 error if access token is missing', async () => {
      await request(app).post('/v1/machines').send(newMachine).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 403 error if logged in machine is not admin', async () => {
      await insertMachines([machineOne]);

      await request(app)
        .post('/v1/machines')
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send(newMachine)
        .expect(httpStatus.FORBIDDEN);
    });

    test('should return 400 error if id is invalid', async () => {
      await insertMachines([admin]);
      newMachine.id = 'invalidId';

      await request(app)
        .post('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newMachine)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if id is already used', async () => {
      await insertMachines([admin, machineOne]);
      newMachine.id = machineOne.id;

      await request(app)
        .post('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newMachine)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password length is less than 8 characters', async () => {
      await insertMachines([admin]);
      newMachine.password = 'passwo1';

      await request(app)
        .post('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newMachine)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if password does not contain both letters and numbers', async () => {
      await insertMachines([admin]);
      newMachine.password = 'password';

      await request(app)
        .post('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newMachine)
        .expect(httpStatus.BAD_REQUEST);

      newMachine.password = '1111111';

      await request(app)
        .post('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newMachine)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if role is neither machine nor admin', async () => {
      await insertMachines([admin]);
      newMachine.role = 'invalid';

      await request(app)
        .post('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(newMachine)
        .expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('GET /v1/machines', () => {
    test('should return 200 and apply the default query options', async () => {
      await insertMachines([machineOne, machineTwo, admin]);

      const res = await request(app)
        .get('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(3);
      expect(res.body.results[0]).toEqual({
        id: machineOne._id.toHexString(),
        name: machineOne.name,
        id: machineOne.id,
        role: machineOne.role,
        isIdVerified: machineOne.isIdVerified,
      });
    });

    test('should return 401 if access token is missing', async () => {
      await insertMachines([machineOne, machineTwo, admin]);

      await request(app).get('/v1/machines').send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 403 if a non-admin is trying to access all machines', async () => {
      await insertMachines([machineOne, machineTwo, admin]);

      await request(app)
        .get('/v1/machines')
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send()
        .expect(httpStatus.FORBIDDEN);
    });

    test('should correctly apply filter on name field', async () => {
      await insertMachines([machineOne, machineTwo, admin]);

      const res = await request(app)
        .get('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ name: machineOne.name })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 1,
      });
      expect(res.body.results).toHaveLength(1);
      expect(res.body.results[0].id).toBe(machineOne._id.toHexString());
    });

    test('should correctly apply filter on role field', async () => {
      await insertMachines([machineOne, machineTwo, admin]);

      const res = await request(app)
        .get('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ role: 'machine' })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 2,
      });
      expect(res.body.results).toHaveLength(2);
      expect(res.body.results[0].id).toBe(machineOne._id.toHexString());
      expect(res.body.results[1].id).toBe(machineTwo._id.toHexString());
    });

    test('should correctly sort the returned array if descending sort param is specified', async () => {
      await insertMachines([machineOne, machineTwo, admin]);

      const res = await request(app)
        .get('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ sortBy: 'role:desc' })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(3);
      expect(res.body.results[0].id).toBe(machineOne._id.toHexString());
      expect(res.body.results[1].id).toBe(machineTwo._id.toHexString());
      expect(res.body.results[2].id).toBe(admin._id.toHexString());
    });

    test('should correctly sort the returned array if ascending sort param is specified', async () => {
      await insertMachines([machineOne, machineTwo, admin]);

      const res = await request(app)
        .get('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ sortBy: 'role:asc' })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(3);
      expect(res.body.results[0].id).toBe(admin._id.toHexString());
      expect(res.body.results[1].id).toBe(machineOne._id.toHexString());
      expect(res.body.results[2].id).toBe(machineTwo._id.toHexString());
    });

    test('should correctly sort the returned array if multiple sorting criteria are specified', async () => {
      await insertMachines([machineOne, machineTwo, admin]);

      const res = await request(app)
        .get('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ sortBy: 'role:desc,name:asc' })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(3);

      const expectedOrder = [machineOne, machineTwo, admin].sort((a, b) => {
        if (a.role < b.role) {
          return 1;
        }
        if (a.role > b.role) {
          return -1;
        }
        return a.name < b.name ? -1 : 1;
      });

      expectedOrder.forEach((machine, index) => {
        expect(res.body.results[index].id).toBe(machine._id.toHexString());
      });
    });

    test('should limit returned array if limit param is specified', async () => {
      await insertMachines([machineOne, machineTwo, admin]);

      const res = await request(app)
        .get('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ limit: 2 })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 2,
        totalPages: 2,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(2);
      expect(res.body.results[0].id).toBe(machineOne._id.toHexString());
      expect(res.body.results[1].id).toBe(machineTwo._id.toHexString());
    });

    test('should return the correct page if page and limit params are specified', async () => {
      await insertMachines([machineOne, machineTwo, admin]);

      const res = await request(app)
        .get('/v1/machines')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .query({ page: 2, limit: 2 })
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 2,
        limit: 2,
        totalPages: 2,
        totalResults: 3,
      });
      expect(res.body.results).toHaveLength(1);
      expect(res.body.results[0].id).toBe(admin._id.toHexString());
    });
  });

  describe('GET /v1/machines/:id', () => {
    test('should return 200 and the machine object if data is ok', async () => {
      await insertMachines([machineOne]);

      const res = await request(app)
        .get(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send()
        .expect(httpStatus.OK);

      expect(res.body).not.toHaveProperty('password');
      expect(res.body).toEqual({
        id: machineOne._id.toHexString(),
        id: machineOne.id,
        name: machineOne.name,
        role: machineOne.role,
        isIdVerified: machineOne.isIdVerified,
      });
    });

    test('should return 401 error if access token is missing', async () => {
      await insertMachines([machineOne]);

      await request(app).get(`/v1/machines/${machineOne._id}`).send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 403 error if machine is trying to get another machine', async () => {
      await insertMachines([machineOne, machineTwo]);

      await request(app)
        .get(`/v1/machines/${machineTwo._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send()
        .expect(httpStatus.FORBIDDEN);
    });

    test('should return 200 and the machine object if admin is trying to get another machine', async () => {
      await insertMachines([machineOne, admin]);

      await request(app)
        .get(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.OK);
    });

    test('should return 400 error if id is not a valid mongo id', async () => {
      await insertMachines([admin]);

      await request(app)
        .get('/v1/machines/invalidId')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 error if machine is not found', async () => {
      await insertMachines([admin]);

      await request(app)
        .get(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.NOT_FOUND);
    });
  });

  describe('DELETE /v1/machines/:id', () => {
    test('should return 204 if data is ok', async () => {
      await insertMachines([machineOne]);

      await request(app)
        .delete(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send()
        .expect(httpStatus.NO_CONTENT);

      const dbMachine = await Machine.findById(machineOne._id);
      expect(dbMachine).toBeNull();
    });

    test('should return 401 error if access token is missing', async () => {
      await insertMachines([machineOne]);

      await request(app).delete(`/v1/machines/${machineOne._id}`).send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 403 error if machine is trying to delete another machine', async () => {
      await insertMachines([machineOne, machineTwo]);

      await request(app)
        .delete(`/v1/machines/${machineTwo._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send()
        .expect(httpStatus.FORBIDDEN);
    });

    test('should return 204 if admin is trying to delete another machine', async () => {
      await insertMachines([machineOne, admin]);

      await request(app)
        .delete(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.NO_CONTENT);
    });

    test('should return 400 error if id is not a valid mongo id', async () => {
      await insertMachines([admin]);

      await request(app)
        .delete('/v1/machines/invalidId')
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 404 error if machine already is not found', async () => {
      await insertMachines([admin]);

      await request(app)
        .delete(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send()
        .expect(httpStatus.NOT_FOUND);
    });
  });

  describe('PATCH /v1/machines/:id', () => {
    test('should return 200 and successfully update machine if data is ok', async () => {
      await insertMachines([machineOne]);
      const updateBody = {
        name: faker.name.findName(),
        id: faker.internet.id().toLowerCase(),
        password: 'newPassword1',
      };

      const res = await request(app)
        .patch(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.OK);

      expect(res.body).not.toHaveProperty('password');
      expect(res.body).toEqual({
        id: machineOne._id.toHexString(),
        name: updateBody.name,
        id: updateBody.id,
        role: 'machine',
        isIdVerified: false,
      });

      const dbMachine = await Machine.findById(machineOne._id);
      expect(dbMachine).toBeDefined();
      expect(dbMachine.password).not.toBe(updateBody.password);
      expect(dbMachine).toMatchObject({ name: updateBody.name, id: updateBody.id, role: 'machine' });
    });

    test('should return 401 error if access token is missing', async () => {
      await insertMachines([machineOne]);
      const updateBody = { name: faker.name.findName() };

      await request(app).patch(`/v1/machines/${machineOne._id}`).send(updateBody).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 403 if machine is updating another machine', async () => {
      await insertMachines([machineOne, machineTwo]);
      const updateBody = { name: faker.name.findName() };

      await request(app)
        .patch(`/v1/machines/${machineTwo._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.FORBIDDEN);
    });

    test('should return 200 and successfully update machine if admin is updating another machine', async () => {
      await insertMachines([machineOne, admin]);
      const updateBody = { name: faker.name.findName() };

      await request(app)
        .patch(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.OK);
    });

    test('should return 404 if admin is updating another machine that is not found', async () => {
      await insertMachines([admin]);
      const updateBody = { name: faker.name.findName() };

      await request(app)
        .patch(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.NOT_FOUND);
    });

    test('should return 400 error if id is not a valid mongo id', async () => {
      await insertMachines([admin]);
      const updateBody = { name: faker.name.findName() };

      await request(app)
        .patch(`/v1/machines/invalidId`)
        .set('Authorization', `Bearer ${adminAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 if id is invalid', async () => {
      await insertMachines([machineOne]);
      const updateBody = { id: 'invalidId' };

      await request(app)
        .patch(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 if id is already taken', async () => {
      await insertMachines([machineOne, machineTwo]);
      const updateBody = { id: machineTwo.id };

      await request(app)
        .patch(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should not return 400 if id is my id', async () => {
      await insertMachines([machineOne]);
      const updateBody = { id: machineOne.id };

      await request(app)
        .patch(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.OK);
    });

    test('should return 400 if password length is less than 8 characters', async () => {
      await insertMachines([machineOne]);
      const updateBody = { password: 'passwo1' };

      await request(app)
        .patch(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 if password does not contain both letters and numbers', async () => {
      await insertMachines([machineOne]);
      const updateBody = { password: 'password' };

      await request(app)
        .patch(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);

      updateBody.password = '11111111';

      await request(app)
        .patch(`/v1/machines/${machineOne._id}`)
        .set('Authorization', `Bearer ${machineOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.BAD_REQUEST);
    });
  });
});
