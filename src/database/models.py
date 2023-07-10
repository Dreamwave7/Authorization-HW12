from sqlalchemy import Column, Integer, String, Boolean, func, Table, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql.schema import ForeignKey
from sqlalchemy.sql.sqltypes import DateTime
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


note_m2m_tag = Table("note_m2m_tag",Base.metadata,
                     Column("id", Integer(), primary_key=True),
                     Column("note_id", Integer(), ForeignKey("notes.id", ondelete="CASCADE")),
                     Column("tag_id", Integer(), ForeignKey("tags.id", ondelete="CASCADE"))
                     
                     )


class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer(), primary_key=True)
    title = Column(String(40), nullable=False)
    created_at = Column("created_at", DateTime, default= func.now)
    description = Column(Boolean, default=False)
    done = Column(Boolean, default=False)
    tags = relationship("Tag", secondary=note_m2m_tag, backref="notes")
    user_id = Column("user_id", ForeignKey("users.id", ondelete="CASCADE"),default= None)
    user = relationship("User",backref="notes")

class Tag(Base):
    __tablename__ = "tags"
    __table_args__ = (
        UniqueConstraint("name", "user_id", name = "unique_tag_user")
        )
    id = Column(Integer(), primary_key=True)
    name = Column(String(30), nullable=False)
    user_id = Column("user_id", ForeignKey("users.id", ondelete="CASCADE"))