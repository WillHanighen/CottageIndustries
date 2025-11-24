#!/bin/bash
# Script to update Cloudflare IP allowlist for Nginx
# This script fetches Cloudflare's IPs and creates an Nginx config file
# that allows only those IPs and denies everyone else.

# Output file path (adjust if your nginx config is elsewhere)
CF_CONF_FILE="/etc/nginx/conf.d/cloudflare_allow.conf"

echo "Updating Cloudflare IP list to $CF_CONF_FILE..."

# Create the file and add the header
echo "# Cloudflare IP Ranges - Auto generated" > $CF_CONF_FILE
echo "# Only allow connections from these IPs" >> $CF_CONF_FILE
echo "" >> $CF_CONF_FILE

# Fetch IPv4
echo "# IPv4" >> $CF_CONF_FILE
for ip in $(curl -s https://www.cloudflare.com/ips-v4); do
    echo "allow $ip;" >> $CF_CONF_FILE
done

echo "" >> $CF_CONF_FILE

# Fetch IPv6
echo "# IPv6" >> $CF_CONF_FILE
for ip in $(curl -s https://www.cloudflare.com/ips-v6); do
    echo "allow $ip;" >> $CF_CONF_FILE
done

echo "" >> $CF_CONF_FILE
echo "# Deny everything else" >> $CF_CONF_FILE
echo "deny all;" >> $CF_CONF_FILE

# Test configuration and reload if valid
echo "Testing Nginx configuration..."
if nginx -t; then
    echo "Configuration valid. Reloading Nginx..."
    systemctl reload nginx
    echo "Done."
else
    echo "Configuration test failed! Nginx was NOT reloaded."
    exit 1
fi

