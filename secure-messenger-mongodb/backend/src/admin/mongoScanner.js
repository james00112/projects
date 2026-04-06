const mongoose = require('mongoose');
const crypto = require('crypto');

class MongoDBSecurityScanner {
  constructor(dbConnection) {
    this.db = dbConnection;
  }
  
  // Check for NoSQL injection vulnerabilities
  async scanNoSQLInjection(collectionName, testPayloads) {
    const collection = this.db.collection(collectionName);
    const results = [];
    
    const defaultPayloads = [
      { $ne: null },
      { $gt: '' },
      { $regex: '.*' },
      { $where: '1 == 1' },
      { username: { $ne: null } }
    ];
    
    const payloads = testPayloads || defaultPayloads;
    
    for (const payload of payloads) {
      try {
        // Test if malicious query can bypass authentication
        const result = await collection.findOne(payload);
        if (result) {
          results.push({
            payload: JSON.stringify(payload),
            vulnerable: true,
            foundDocument: result._id
          });
        } else {
          results.push({
            payload: JSON.stringify(payload),
            vulnerable: false
          });
        }
      } catch (err) {
        results.push({
          payload: JSON.stringify(payload),
          vulnerable: false,
          error: err.message
        });
      }
    }
    
    return results;
  }
  
  // Check for exposed sensitive fields
  async scanExposedFields() {
    const collections = await this.db.listCollections().toArray();
    const sensitiveFields = ['password', 'secret', 'token', 'key', 'private', 'credit_card'];
    const exposed = [];
    
    for (const collection of collections) {
      const sample = await this.db.collection(collection.name).findOne({});
      if (sample) {
        const fields = Object.keys(sample);
        const exposedFields = fields.filter(field => 
          sensitiveFields.some(sensitive => field.toLowerCase().includes(sensitive))
        );
        
        if (exposedFields.length > 0) {
          exposed.push({
            collection: collection.name,
            exposedFields
          });
        }
      }
    }
    
    return exposed;
  }
  
  // Check index coverage for performance & security
  async scanMissingIndexes() {
    const collections = await this.db.listCollections().toArray();
    const recommendations = [];
    
    for (const collection of collections) {
      const indexes = await this.db.collection(collection.name).indexes();
      const indexedFields = indexes.flatMap(idx => Object.keys(idx.key));
      
      // Check for common missing indexes
      const requiredIndexes = ['userId', 'createdAt', 'conversationId', 'email', 'username'];
      
      for (const field of requiredIndexes) {
        if (!indexedFields.includes(field)) {
          recommendations.push({
            collection: collection.name,
            missingIndex: field,
            suggestion: `db.${collection.name}.createIndex({ "${field}": 1 })`
          });
        }
      }
    }
    
    return recommendations;
  }
  
  // Check for unencrypted sensitive data
  async scanUnencryptedData() {
    const collections = await this.db.listCollections().toArray();
    const unencryptedData = [];
    
    for (const collection of collections) {
      const sample = await this.db.collection(collection.name).findOne({});
      if (sample) {
        const checkFields = (obj, path = '') => {
          for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string' && value.length > 0) {
              if (key.toLowerCase().includes('message') || 
                  key.toLowerCase().includes('content') ||
                  key.toLowerCase().includes('text')) {
                // Check if appears to be unencrypted (not base64 or too short)
                if (!value.match(/^[A-Za-z0-9+/=]+$/) && value.length > 20) {
                  unencryptedData.push({
                    collection: collection.name,
                    field: path + key,
                    sample: value.substring(0, 50)
                  });
                }
              }
            } else if (typeof value === 'object' && value !== null) {
              checkFields(value, `${path}${key}.`);
            }
          }
        };
        
        checkFields(sample);
      }
    }
    
    return unencryptedData;
  }
  
  // Check for weak password hashes
  async scanWeakPasswordHashes() {
    const users = await this.db.collection('users').find({}).toArray();
    const weakHashes = [];
    
    for (const user of users) {
      if (user.passwordHash) {
        // Check for md5 (32 chars hex) or sha1 (40 chars hex) patterns
        if (user.passwordHash.match(/^[a-f0-9]{32}$/)) {
          weakHashes.push({
            userId: user._id,
            username: user.username,
            hashType: 'MD5',
            risk: 'CRITICAL'
          });
        } else if (user.passwordHash.match(/^[a-f0-9]{40}$/)) {
          weakHashes.push({
            userId: user._id,
            username: user.username,
            hashType: 'SHA1',
            risk: 'HIGH'
          });
        } else if (!user.passwordHash.startsWith('$2')) {
          weakHashes.push({
            userId: user._id,
            username: user.username,
            hashType: 'Unknown/Weak',
            risk: 'MEDIUM'
          });
        }
      }
    }
    
    return weakHashes;
  }
  
  // Run full database security audit
  async fullDatabaseAudit() {
    console.log('🔍 Starting MongoDB Security Audit...');
    
    const [
      noSqlInjection,
      exposedFields,
      missingIndexes,
      unencryptedData,
      weakPasswords
    ] = await Promise.all([
      this.scanNoSQLInjection('users'),
      this.scanExposedFields(),
      this.scanMissingIndexes(),
      this.scanUnencryptedData(),
      this.scanWeakPasswordHashes()
    ]);
    
    const riskLevel = 
      noSqlInjection.some(r => r.vulnerable) ? 'CRITICAL' :
      weakPasswords.length > 0 ? 'HIGH' :
      unencryptedData.length > 0 ? 'MEDIUM' :
      exposedFields.length > 0 ? 'LOW' : 'SECURE';
    
    return {
      timestamp: new Date(),
      riskLevel,
      databaseName: this.db.databaseName,
      scans: {
        noSqlInjection,
        exposedFields,
        missingIndexes,
        unencryptedData,
        weakPasswords
      },
      recommendations: [
        ...(noSqlInjection.some(r => r.vulnerable) ? ['CRITICAL: Fix NoSQL injection vulnerabilities immediately - use parameterized queries'] : []),
        ...(weakPasswords.length > 0 ? [`Upgrade ${weakPasswords.length} users to bcrypt password hashing`] : []),
        ...(unencryptedData.length > 0 ? [`Encrypt sensitive fields: ${unencryptedData.map(u => u.field).join(', ')}`] : []),
        ...(exposedFields.length > 0 ? [`Remove or encrypt exposed sensitive fields: ${exposedFields.map(e => e.collection + ': ' + e.exposedFields.join(', ')).join('; ')}`] : []),
        ...(missingIndexes.length > 0 ? [`Add missing indexes: ${missingIndexes.map(m => m.suggestion).join('; ')}`] : [])
      ],
      remediationSteps: this.generateRemediationPlan(riskLevel, { noSqlInjection, weakPasswords, unencryptedData })
    };
  }
  
  generateRemediationPlan(riskLevel, issues) {
    const plan = {
      immediate: [],
      shortTerm: [],
      longTerm: []
    };
    
    if (issues.noSqlInjection.some(r => r.vulnerable)) {
      plan.immediate.push('Implement mongoose schema validation for all inputs');
      plan.immediate.push('Use express-mongo-sanitize middleware');
      plan.immediate.push('Review all $where and $regex queries');
    }
    
    if (issues.weakPasswords.length > 0) {
      plan.immediate.push('Force password reset for users with weak hashes');
      plan.shortTerm.push('Implement bcrypt with cost factor 12+');
    }
    
    if (issues.unencryptedData.length > 0) {
      plan.shortTerm.push('Implement field-level encryption for sensitive data');
      plan.longTerm.push('Consider MongoDB Atlas encryption at rest');
    }
    
    return plan;
  }
}

module.exports = MongoDBSecurityScanner;