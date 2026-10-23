FROM php:7.4-apache

# pdo_sqlite and sqlite3 ship with the official PHP image, so no extra
# packages are needed (installing them from Debian bullseye now fails).

# Enable Apache rewrite module
RUN a2enmod rewrite

# Set working directory
WORKDIR /var/www/html

# Copy web files
COPY . /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html

# Expose port 80
EXPOSE 80

# Start Apache
CMD ["apache2-foreground"]
