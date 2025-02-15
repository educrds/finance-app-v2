export interface User {
  name: string;
  email: string;
  admin?: boolean | number;
}

export interface Users {
  usr_id: number;
  usr_nome: string;
  usr_email: string;
  usr_last_access: Date;
  usr_created_at: Date;
  admin: number | null;
}
