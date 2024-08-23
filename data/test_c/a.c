void println(const char * ln)
{
  if(ln != NULL)
  printf("%s\n", ln);
}

void func()
{
  char *data;
  char dataBuffer[100];
  memset(dataBuffer, 'A', 99);
  dataBuffer[99] = '\0';
  while(1)
  {
    data = dataBuffer - 8;
    break;
  }
  println(data);
}