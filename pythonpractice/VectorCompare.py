import math


class VectorCompare:
  
  def magnitude(self,concordance):
    if type(concordance) != dict:
      raise ValueError('Supplied Argument should be of type dict')
    total = 0
    for word,count in concordance.iteritems():
      total += count ** 2
    return math.sqrt(total)

  def relation(self,concordance1, concordance2):
    if type(concordance1) != dict:
      raise ValueError('Supplied Argument 1 should be of type dict')
    if type(concordance2) != dict:
      raise ValueError('Supplied Argument 2 should be of type dict')
    relevance = 0
    topvalue = 0
    for word, count in concordance1.iteritems():
      if concordance2.has_key(word):
        topvalue += count * concordance2[word]
    if (self.magnitude(concordance1) * self.magnitude(concordance2)) != 0:
      return topvalue / (self.magnitude(concordance1) * self.magnitude(concordance2))
    else:
      return 0

  def concordance(self,document):
    if type(document) != str:
      raise ValueError('Supplied Argument should be of type string')
    con = {}
    for word in document.split(' '):
      if con.has_key(word):
        con[word] = con[word] + 1
      else:
        con[word] = 1
    return con
