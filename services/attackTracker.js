// services/attackTracker.js
const EventEmitter = require('events');

class AttackTracker extends EventEmitter {
    constructor() {
        super();
        this.activeAttacks = new Map();
        this.attackCounter = 0;
        this.cleanupInterval = setInterval(() => this.cleanupExpiredAttacks(), 5000);
    }
    
    registerAttack(attackData) {
        const attackId = this.generateAttackId();
        const now = Date.now();
        const durationMs = attackData.duration * 1000;
        
        const attack = {
            attackId,
            target: attackData.target,
            port: attackData.port,
            duration: attackData.duration,
            startedAt: now,
            expiresAt: now + durationMs,
            username: attackData.username,
            userId: attackData.userId,
            source: attackData.source,
            status: 'running'
        };
        
        this.activeAttacks.set(attackId, attack);
        this.attackCounter++;
        
        return attackId;
    }
    
    getActiveAttacks() {
        const attacks = Array.from(this.activeAttacks.values());
        const now = Date.now();
        
        // DEBUG: Log what's in the map
        if (attacks.length > 0) {
            attacks.forEach(a => {
                const timeLeft = (a.expiresAt - now) / 1000;
            });
        }
        
        return attacks;
    }
    
    getStats() {
        const attacks = this.getActiveAttacks();
        const bySource = {
            api: attacks.filter(a => a.source === 'api').length,
            panel: attacks.filter(a => a.source === 'panel').length
        };
        
        
        return {
            totalActive: attacks.length,
            bySource,
            attacks: attacks.map(a => ({
                attackId: a.attackId,
                target: a.target,
                port: a.port,
                duration: a.duration,
                startedAt: a.startedAt,
                expiresAt: a.expiresAt,
                timeRemaining: Math.max(0, Math.floor((a.expiresAt - Date.now()) / 1000)),
                username: a.username,
                source: a.source,
                status: a.status
            })),
            totalAttacksLaunched: this.attackCounter,
            timestamp: Date.now()
        };
    }
    
    cleanupExpiredAttacks() {
        const now = Date.now();
        let cleaned = 0;
        
        
        for (const [attackId, attack] of this.activeAttacks) {
            const timeLeft = (attack.expiresAt - now) / 1000;
            console.log(`  - ${attackId}: expires in ${timeLeft.toFixed(2)}s`);
            
            if (attack.expiresAt <= now) {
                this.activeAttacks.delete(attackId);
                cleaned++;
                this.emit('attackExpired', attack);
            }
        }
        
        if (cleaned > 0) {
        }
    }
    
    generateAttackId() {
        return `att_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }
    
    stopAttack(attackId) {
        const attack = this.activeAttacks.get(attackId);
        if (attack) {
            attack.status = 'stopped';
            attack.stoppedAt = Date.now();
            this.activeAttacks.delete(attackId);
            this.emit('attackStopped', attack);
            return true;
        }
        return false;
    }
    
    stopUserAttacks(userId) {
        let stopped = 0;
        for (const [attackId, attack] of this.activeAttacks) {
            if (attack.userId === userId) {
                this.stopAttack(attackId);
                stopped++;
            }
        }
        return stopped;
    }
    
    getUserAttacks(userId) {
        return Array.from(this.activeAttacks.values())
            .filter(attack => attack.userId === userId);
    }
    
    shutdown() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        this.activeAttacks.clear();
    }
}

const attackTracker = new AttackTracker();
module.exports = attackTracker;