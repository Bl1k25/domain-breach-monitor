from django import forms
from .models import CorporateDomain


class CorporateDomainForm(forms.ModelForm):
    class Meta:
        model = CorporateDomain
        fields = ['name', 'owner', 'criticality', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'например, company.ru'
            }),
            'owner': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Иванов И.И.'
            }),
            'criticality': forms.Select(attrs={'class': 'form-select'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }