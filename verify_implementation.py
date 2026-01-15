#!/usr/bin/env python3
"""
Quick verification script for LDAP Bind Proxy implementation.
Checks that all TLS features are properly implemented.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check_imports():
    """Check that all necessary modules can be imported."""
    print("Checking imports...")
    try:
        from ldap_bind_proxy import Configuration, OidcProxy, create_ssl_context_factory
        print("✓ Core modules imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        print("  Run: pip install -r requirements.txt")
        return False

def check_configuration():
    """Check Configuration class."""
    print("\nChecking Configuration class...")
    try:
        from ldap_bind_proxy import Configuration
        
        # Check default values
        config = Configuration()
        
        checks = [
            (config.tls_port == 636, "Default TLS port is 636"),
            (config.plain_port == 389, "Default plain port is 389"),
            (hasattr(config, 'tls_certfile'), "Has tls_certfile attribute"),
            (hasattr(config, 'tls_keyfile'), "Has tls_keyfile attribute"),
            (hasattr(config, 'tls_cafile'), "Has tls_cafile attribute"),
            (hasattr(config, 'require_client_cert'), "Has require_client_cert attribute"),
            (hasattr(config, 'enable_starttls'), "Has enable_starttls attribute"),
        ]
        
        all_passed = True
        for check, description in checks:
            if check:
                print(f"  ✓ {description}")
            else:
                print(f"  ✗ {description}")
                all_passed = False
        
        return all_passed
    except Exception as e:
        print(f"✗ Configuration check failed: {e}")
        return False

def check_oidc_proxy():
    """Check OidcProxy class."""
    print("\nChecking OidcProxy class...")
    try:
        from ldap_bind_proxy import OidcProxy, Configuration
        
        config = Configuration()
        proxy = OidcProxy(config, None)
        
        checks = [
            (hasattr(proxy, 'STARTTLS_OID'), "Has STARTTLS_OID constant"),
            (proxy.STARTTLS_OID == '1.3.6.1.4.1.1466.20037', "Correct STARTTLS OID"),
            (hasattr(proxy, 'tls_started'), "Has tls_started flag"),
            (hasattr(proxy, 'ssl_context_factory'), "Has ssl_context_factory attribute"),
            (hasattr(proxy, 'handleBeforeForwardRequest'), "Has handleBeforeForwardRequest method"),
        ]
        
        all_passed = True
        for check, description in checks:
            if check:
                print(f"  ✓ {description}")
            else:
                print(f"  ✗ {description}")
                all_passed = False
        
        return all_passed
    except Exception as e:
        print(f"✗ OidcProxy check failed: {e}")
        return False

def check_ssl_context_factory():
    """Check SSL context factory function."""
    print("\nChecking SSL context factory...")
    try:
        from ldap_bind_proxy import create_ssl_context_factory, Configuration
        
        # Check with no certs configured
        config = Configuration()
        result = create_ssl_context_factory(config)
        
        if result is None:
            print("  ✓ Returns None when no certificates configured")
            return True
        else:
            print("  ✗ Should return None when no certificates configured")
            return False
    except Exception as e:
        print(f"✗ SSL context factory check failed: {e}")
        return False

def check_file_structure():
    """Check that all expected files exist."""
    print("\nChecking file structure...")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    expected_files = [
        'ldap_bind_proxy.py',
        'requirements.txt',
        'requirements-test.txt',
        'README.md',
        'TLS-GUIDE.md',
        'SETUP.md',
        'tests/__init__.py',
        'tests/test_tls_support.py',
        'tests/test_integration.py',
        'run_tests.sh',
    ]
    
    all_exist = True
    for file_path in expected_files:
        full_path = os.path.join(base_dir, file_path)
        if os.path.exists(full_path):
            print(f"  ✓ {file_path}")
        else:
            print(f"  ✗ {file_path} (missing)")
            all_exist = False
    
    return all_exist

def main():
    """Run all verification checks."""
    print("="*60)
    print("LDAP Bind Proxy - Implementation Verification")
    print("="*60)
    
    results = []
    
    # Run checks
    results.append(("File Structure", check_file_structure()))
    results.append(("Module Imports", check_imports()))
    
    # Only run these if imports succeeded
    if results[-1][1]:
        results.append(("Configuration", check_configuration()))
        results.append(("OidcProxy", check_oidc_proxy()))
        results.append(("SSL Context Factory", check_ssl_context_factory()))
    
    # Print summary
    print("\n" + "="*60)
    print("Verification Summary")
    print("="*60)
    
    all_passed = True
    for name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{name:30} {status}")
        if not passed:
            all_passed = False
    
    print("="*60)
    
    if all_passed:
        print("\n✓ All checks passed! Implementation is ready.")
        print("\nNext steps:")
        print("  1. Run tests: ./run_tests.sh")
        print("  2. Generate certificates: python tests/test_integration.py --generate-certs ./certs")
        print("  3. Configure environment variables (see SETUP.md)")
        print("  4. Start proxy: python ldap_bind_proxy.py")
        return 0
    else:
        print("\n✗ Some checks failed. Please review the errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
