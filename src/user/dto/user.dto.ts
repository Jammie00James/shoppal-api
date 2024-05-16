import { IsMongoId, IsNotEmpty} from 'class-validator';

export class GetUserDto {
  @IsNotEmpty()
  @IsMongoId()
  id: string;
}