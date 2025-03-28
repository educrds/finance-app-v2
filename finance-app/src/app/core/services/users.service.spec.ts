import { TestBed } from "@angular/core/testing";
import { UsersService } from "./users.service";
import { Users } from "../models/User";
import { HttpClient } from "@angular/common/http";
import { of } from "rxjs";

describe(UsersService.name, () => {
  let usersService: UsersService;
  let httpClientSpy: jasmine.SpyObj<HttpClient>;

  beforeEach(() => {
    httpClientSpy = jasmine.createSpyObj('HttpClient', ['post']);

    TestBed.configureTestingModule({
      providers: [
        UsersService,
        { provide: HttpClient, useValue: httpClientSpy }
      ]
    });

    usersService = TestBed.inject(UsersService);
  });

  it(`${UsersService.prototype.getUsersList$.name} deve retornar lista de usuários.`, () => {
    const expectedUsersList: Users[] = [
      {
        usr_id: 1,
        usr_nome: "Edu",
        usr_email: "edu@gmail.com",
        usr_last_access: new Date(2025, 4, 10),
        usr_created_at: new Date(2025, 2, 23),
        admin: 1,
      },
      {
        usr_id: 2,
        usr_nome: "Josi",
        usr_email: "josi@gmail.com",
        usr_last_access: new Date(2025, 6, 1),
        usr_created_at: new Date(2025, 4, 3),
        admin: 1,
      },
    ];

    httpClientSpy.post.and.returnValue(of(expectedUsersList))
    usersService.getUsersList$().subscribe(response => expect(response).toEqual(expectedUsersList));
  });
});
