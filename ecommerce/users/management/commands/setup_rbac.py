from django.core.management.base import BaseCommand
from django.db import transaction
from users.models import Role, Permission

class Command(BaseCommand):
    help = 'Setup RBAC roles and permissions'

    @transaction.atomic
    def handle(self, *args, **kwargs):
        # Create permissions
        permissions_data = [
            # User management
            {'name': 'View Users', 'resource': 'user', 'action': 'view'},
            {'name': 'Create Users', 'resource': 'user', 'action': 'create'},
            {'name': 'Update Users', 'resource': 'user', 'action': 'update'},
            {'name': 'Delete Users', 'resource': 'user', 'action': 'delete'},
            
            # Product management
            {'name': 'View Products', 'resource': 'product', 'action': 'view'},
            {'name': 'Create Products', 'resource': 'product', 'action': 'create'},
            {'name': 'Update Products', 'resource': 'product', 'action': 'update'},
            {'name': 'Delete Products', 'resource': 'product', 'action': 'delete'},
            
            # Order management
            {'name': 'View Orders', 'resource': 'order', 'action': 'view'},
            {'name': 'Create Orders', 'resource': 'order', 'action': 'create'},
            {'name': 'Update Orders', 'resource': 'order', 'action': 'update'},
            {'name': 'Cancel Orders', 'resource': 'order', 'action': 'cancel'},
            
            # Category management
            {'name': 'View Categories', 'resource': 'category', 'action': 'view'},
            {'name': 'Manage Categories', 'resource': 'category', 'action': 'manage'},
        ]

        permissions = {}
        for perm_data in permissions_data:
            perm, created = Permission.objects.get_or_create(**perm_data)
            permissions[perm.codename] = perm
            if created:
                self.stdout.write(f'Created permission: {perm.codename}')

        # Create roles
        admin_role, created = Role.objects.get_or_create(
            name=Role.ADMIN,
            defaults={'description': 'Full system access'}
        )
        if created:
            admin_role.permissions.set(Permission.objects.all())
            self.stdout.write(self.style.SUCCESS('Created Admin role'))

        seller_role, created = Role.objects.get_or_create(
            name=Role.SELLER,
            defaults={'description': 'Can manage own products and orders'}
        )
        if created:
            seller_permissions = [
                'product_view', 'product_create', 'product_update', 'product_delete',
                'order_view', 'order_update', 'category_view'
            ]
            seller_role.permissions.set([permissions[p] for p in seller_permissions])
            self.stdout.write(self.style.SUCCESS('Created Seller role'))

        customer_role, created = Role.objects.get_or_create(
            name=Role.CUSTOMER,
            defaults={'description': 'Can browse and purchase products'}
        )
        if created:
            customer_permissions = [
                'product_view', 'category_view', 'order_view', 'order_create', 'order_cancel'
            ]
            customer_role.permissions.set([permissions[p] for p in customer_permissions])
            self.stdout.write(self.style.SUCCESS('Created Customer role'))

        self.stdout.write(self.style.SUCCESS('RBAC setup completed successfully!'))

