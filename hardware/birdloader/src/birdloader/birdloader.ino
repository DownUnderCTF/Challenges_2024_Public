#include <SPI.h>
#include <SoftwareSerial.h>

SoftwareSerial mySerial(PD0, PD1);
void setup()
{
  mySerial.begin(9600);

  // SPI Slave
  pinMode(MISO, OUTPUT);
  SPCR |= _BV(SPE);
  SPI.attachInterrupt();
}

volatile byte rx_pos = 0xFF;
byte challenge_info[] = {
    0x00, 0x00, 0x00,
    0x43, 0x46, 0x43, 0x31,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03,
    0xD7, 0x1B, 0x49, 0x4B};

// SPI slave
ISR(SPI_STC_vect)
{
  byte c = SPDR; // grab byte from SPI Data Register

  if (c == 0x03) // read
  {
    rx_pos = 0;
  }

  if (rx_pos < sizeof(challenge_info))
  {
    SPDR = challenge_info[rx_pos++];
  }

} // end of interrupt routine SPI_STC_vect

char expected_password[17] = "4572381552009517"; // Chosen by fair dice roll

char readCharBlocking()
{
  int result = -1;

  while (result == -1)
    result = mySerial.read();

  return (char)result;
}

int debug_commands_unlocked = 0;

void loop()
{
  // put your main code here, to run repeatedly:
  mySerial.write("Your command> ");

  char command[64] = {0};
  for (int i = 0; i < 63; i++)
  {
    int val = readCharBlocking();
    if (val == '\n' || val == '\r')
      break;
    command[i] = val;
  }

  if (command[0] == 'l')
  {
    mySerial.write("Loading bird...\r\n");
    delay(1000);
    mySerial.write("...\r\n");
    delay(1000);
    mySerial.write("...\r\n");
    delay(1000);
    mySerial.write("...\r\n");
    delay(1000);
    mySerial.write("Loaded!\r\n");
    mySerial.write(" ______ \r\n");
    mySerial.write("|      |\r\n");
    mySerial.write("|  🦆  |\r\n");
    mySerial.write("|______|\r\n");
  }
  else if (command[0] == 'd')
  {
    mySerial.write("Enter debug PIN (16 digits)> \r\n");
    char password[64] = {0};

    for (int i = 0; i < 63; i++)
    {

      int val = readCharBlocking();
      if (val == '\n' || val == '\r')
        break;
      password[i] = val;
    }

    noInterrupts();
    mySerial.write("Checking...\r\n");
    mySerial.flush();
    if (strcmp(password, expected_password) == 0)
    {
      mySerial.write("Debug commands unlocked\r\n");
      mySerial.flush();
      debug_commands_unlocked = 1;
    }
    else
    {
      mySerial.write("Incorrect PIN.\r\n");
      mySerial.flush();
    }
    interrupts();
  }
  else if (command[0] == 'f')
  {
    if (debug_commands_unlocked)
    {
      mySerial.write("DUCTF{are_kiwis_really_birds_if_they_cant_fly}\r\n");
    }
    else
    {
      mySerial.write("This command is locked.\r\n");
    }
  }
  else
  {
    mySerial.write("\r\n  _     _         _ _                 _           \r\n | |   (_)       | | |               | |          \r\n | |__  _ _ __ __| | | ___   __ _  __| | ___ _ __ \r\n | '_ \\| | '__/ _` | |/ _ \\ / _` |/ _` |/ _ \\ '__|\r\n | |_) | | | | (_| | | (_) | (_| | (_| |  __/ |   \r\n |_.__/|_|_|  \\__,_|_|\\___/ \\__,_|\\__,_|\\___|_|   \r\n\r\nMenu options:\r\n * l: Load bird\r\n * d: Unlock debug commands\r\n * f: Get flag\r\n");
  }
}
