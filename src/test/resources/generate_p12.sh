# Download the certificate from the website and name it as certificate.cer

cd certs

# Remove old p12
rm -rf truststore.p12

# Create p12 truststore
keytool -importcert \
  -keystore truststore.p12 \
  -storepass truststore \
  -file certificate.cer \
  -noprompt \
  -alias certificate

# List certificate
keytool -list \
  -v \
  -keystore truststore.p12 \
  -storepass truststore

cd ..