from random import randint
class Keys():
  def __init__(self, p, q, g):
    self.pk = 0
    self.__pvk = 0
    self.simetricKey = 0
    self.p = p
    self.q = q
    self.g = g

  def change_pvk(self):
    pvk = randint(2, self.q-1)
    if pvk in range(2, self.q):
      self.__pvk = pvk
      print(f"Llave privada generada exitosamente: {self.__pvk}")
      return  
    print(f"La llave privada debe estar entre 2 y {self.q-1} (incluyéndolos)")

  def generate_public_key(self):
    if self.__pvk == 0:
      print("Primero crea tu llave privada")
      return
    self.pk = pow(self.g, self.__pvk, self.p)
    print(f"Llave pública generada exitosamente: {self.pk}")

  def generate_simetric_key(self, A):
    if self.pk == 0:
      print("Genera tus 2 llaves primero")
      return
    self.simetricKey = pow(A, self.__pvk, self.p)
    print(f"Llave simétrica generada exitosamente: {self.simetricKey}")
