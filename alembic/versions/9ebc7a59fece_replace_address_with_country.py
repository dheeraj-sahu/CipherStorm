"""replace_address_with_country

Revision ID: 9ebc7a59fece
Revises: 35942c1042e3
Create Date: 2025-07-13 20:11:17.230841

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy import engine_from_config
from alembic import context


# revision identifiers, used by Alembic.
revision: str = '9ebc7a59fece'
down_revision: Union[str, Sequence[str], None] = '35942c1042e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create a new temporary table with the desired schema
    op.create_table(
        'profiles_new',
        sa.Column('profile_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('full_name', sa.String(length=100), nullable=True),
        sa.Column('mobile_no', sa.String(length=20), nullable=True),
        sa.Column('upi_id', sa.String(length=50), nullable=True),
        sa.Column('country', sa.String(length=100), nullable=False, server_default='India'),
        sa.Column('transaction_limit', sa.DECIMAL(precision=10, scale=2), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('profile_id')
    )
    op.create_index('ix_profiles_new_profile_id', 'profiles_new', ['profile_id'])

    # Copy data from the old table to the new table
    op.execute(
        """
        INSERT INTO profiles_new (
            profile_id, user_id, full_name, mobile_no, upi_id,
            country, transaction_limit, created_at
        )
        SELECT
            profile_id, user_id, full_name, mobile_no, upi_id,
            'India', transaction_limit, created_at
        FROM profiles
        """
    )

    # Drop the old table
    op.drop_table('profiles')

    # Rename the new table to the original name
    op.rename_table('profiles_new', 'profiles')


def downgrade() -> None:
    """Downgrade schema."""
    # Create a new temporary table with the old schema
    op.create_table(
        'profiles_old',
        sa.Column('profile_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('full_name', sa.String(length=100), nullable=True),
        sa.Column('mobile_no', sa.String(length=20), nullable=True),
        sa.Column('upi_id', sa.String(length=50), nullable=True),
        sa.Column('address', sa.Text(), nullable=True),
        sa.Column('transaction_limit', sa.DECIMAL(precision=10, scale=2), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('profile_id')
    )
    op.create_index('ix_profiles_old_profile_id', 'profiles_old', ['profile_id'])

    # Copy data from the current table to the old schema table
    op.execute(
        """
        INSERT INTO profiles_old (
            profile_id, user_id, full_name, mobile_no, upi_id,
            address, transaction_limit, created_at
        )
        SELECT
            profile_id, user_id, full_name, mobile_no, upi_id,
            country, transaction_limit, created_at
        FROM profiles
        """
    )

    # Drop the current table
    op.drop_table('profiles')

    # Rename the old schema table to the original name
    op.rename_table('profiles_old', 'profiles')
