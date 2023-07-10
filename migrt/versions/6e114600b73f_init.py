"""Init

Revision ID: 6e114600b73f
Revises: cf5059a0bec2
Create Date: 2023-07-02 21:34:14.714206

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6e114600b73f'
down_revision = 'cf5059a0bec2'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('contacts', sa.Column('lastname', sa.String(length=100), nullable=False))
    op.drop_column('contacts', 'LastName')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('contacts', sa.Column('LastName', sa.VARCHAR(length=100), autoincrement=False, nullable=False))
    op.drop_column('contacts', 'lastname')
    # ### end Alembic commands ###
