from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import User, Base, Catalog, Item

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

catagory1 = Catalog(name="Soccer")
session.add(catagory1)
session.commit()

catagory2 = Catalog(name="Basketball")
session.add(catagory2)
session.commit()

catagory3 = Catalog(name="Baseball")
session.add(catagory3)
session.commit()

catagory4 = Catalog(name="Frisbee")
session.add(catagory4)
session.commit()

catagory5 = Catalog(name="Snowboarding")
session.add(catagory5)
session.commit()

catagory6 = Catalog(name="Rock Climbing")
session.add(catagory6)
session.commit()

catagory7 = Catalog(name="Football")
session.add(catagory7)
session.commit()

catagory8 = Catalog(name="Skating")
session.add(catagory8)
session.commit()

catagory9 = Catalog(name="Hockey")
session.add(catagory9)
session.commit()