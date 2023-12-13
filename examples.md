curl -X POST "http://localhost:8080/osv/purl" \
-H "Content-Type: application/json" \
-d '{"purl": "pkg:npm/strapi-admin"}'

curl -X POST "http://localhost:8080/cve/purl" \
-H "Content-Type: application/json" \
-d '{"purl": "pkg:npm/strapi-admin"}'