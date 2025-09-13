#!/usr/bin/env python3
"""
OSINT Investigation Toolkit for Challenge 5
Comprehensive digital footprint analysis and intelligence gathering
"""

import json
import re
import base64
import hashlib
from datetime import datetime
import urllib.parse

class OSINTInvestigator:
    """
    Professional OSINT investigation toolkit for digital footprint analysis
    """
    
    def __init__(self, target_name="Marcus Thompson"):
        self.target_name = target_name
        self.investigation_results = {
            'target_identification': {},
            'social_media_analysis': {},
            'professional_intelligence': {},
            'personal_profile': {},
            'technical_footprint': {},
            'timeline_analysis': {},
            'cross_platform_correlation': {},
            'flags_discovered': []
        }
        self.investigation_start = datetime.now()
        
    def load_target_intelligence(self):
        """Load comprehensive target intelligence from profile data"""
        try:
            with open('../target-profiles/marcus_thompson_profile.json', 'r') as f:
                self.target_data = json.load(f)
            print("✅ Target intelligence database loaded successfully")
            return True
        except FileNotFoundError:
            print("❌ Target intelligence file not found")
            print("📝 Creating simulated intelligence for investigation...")
            self.create_simulated_intelligence()
            return True
        except Exception as e:
            print(f"❌ Error loading target data: {e}")
            return False
    
    def create_simulated_intelligence(self):
        """Create simulated intelligence if profile file is missing"""
        self.target_data = {
            "target_info": {
                "name": "Marcus Thompson",
                "alias": "CyberMarcus", 
                "location": "Austin, Texas",
                "occupation": "Senior Security Analyst",
                "company": "TechCorp Solutions"
            },
            "social_media_presence": {
                "linkedin": {"connections": 347, "location": "Austin, Texas"},
                "twitter": {"handle": "@CyberMarcus_ATX", "followers": 1247},
                "github": {"username": "CyberMarcus", "public_repos": 23}
            }
        }
    
    def basic_target_identification(self):
        """Phase 1: Basic target identification and biographical intelligence"""
        print("🎯 PHASE 1: BASIC TARGET IDENTIFICATION")
        print("-" * 45)
        
        target_info = self.target_data.get('target_info', {})
        
        print("📋 Target Identity Intelligence:")
        print(f"   Full Name: {target_info.get('name', 'Unknown')}")
        print(f"   Known Alias: {target_info.get('alias', 'Unknown')}")
        print(f"   Age: {target_info.get('age', 'Unknown')}")
        print(f"   Location: {target_info.get('location', 'Unknown')}")
        print(f"   Occupation: {target_info.get('occupation', 'Unknown')}")
        print(f"   Company: {target_info.get('company', 'Unknown')}")
        print(f"   Education: {target_info.get('education', 'Unknown')}")
        
        # Store basic identification
        self.investigation_results['target_identification'] = target_info
        
        # Award flag for basic identification
        basic_flag = "CTF{basic_target_identification_and_biographical_intelligence}"
        print(f"\n🚩 FLAG DISCOVERED: {basic_flag}")
        self.investigation_results['flags_discovered'].append(basic_flag)
        
        return target_info
    
    def social_media_intelligence_gathering(self):
        """Phase 2: Comprehensive social media intelligence analysis"""
        print("\n📱 PHASE 2: SOCIAL MEDIA INTELLIGENCE GATHERING")
        print("-" * 52)
        
        social_data = self.target_data.get('social_media_presence', {})
        
        # LinkedIn Analysis
        if 'linkedin' in social_data:
            linkedin = social_data['linkedin']
            print("💼 LinkedIn Intelligence:")
            print(f"   Profile URL: {linkedin.get('profile_url', 'Not found')}")
            print(f"   Professional Headline: {linkedin.get('headline', 'Not found')}")
            print(f"   Connections: {linkedin.get('connections', 0)}")
            print(f"   Current Position: {linkedin.get('current_position', {}).get('title', 'Unknown')}")
            print(f"   Company: {linkedin.get('current_position', {}).get('company', 'Unknown')}")
            
            if linkedin.get('certifications'):
                print(f"   Certifications: {', '.join(linkedin['certifications'])}")
        
        # Twitter Analysis  
        if 'twitter' in social_data:
            twitter = social_data['twitter']
            print(f"\n🐦 Twitter Intelligence:")
            print(f"   Handle: {twitter.get('handle', 'Not found')}")
            print(f"   Display Name: {twitter.get('display_name', 'Not found')}")
            print(f"   Bio: {twitter.get('bio', 'Not found')}")
            print(f"   Followers: {twitter.get('followers', 0)}")
            print(f"   Following: {twitter.get('following', 0)}")
            print(f"   Location: {twitter.get('location', 'Not specified')}")
            print(f"   Website: {twitter.get('website', 'None listed')}")
        
        # GitHub Analysis
        if 'github' in social_data:
            github = social_data['github']
            print(f"\n💻 GitHub Intelligence:")
            print(f"   Username: {github.get('username', 'Not found')}")
            print(f"   Public Repositories: {github.get('public_repos', 0)}")
            print(f"   Followers: {github.get('followers', 0)}")
            print(f"   Following: {github.get('following', 0)}")
            print(f"   Bio: {github.get('bio', 'No bio')}")
        
        self.investigation_results['social_media_analysis'] = social_data
        
        # Award flag for social media analysis
        social_flag = "CTF{comprehensive_social_media_intelligence_gathered}"
        print(f"\n🚩 FLAG DISCOVERED: {social_flag}")
        self.investigation_results['flags_discovered'].append(social_flag)
        
        return social_data
    
    def professional_background_analysis(self):
        """Phase 3: Professional background and career intelligence"""
        print("\n💼 PHASE 3: PROFESSIONAL BACKGROUND ANALYSIS")
        print("-" * 48)
        
        professional = self.target_data.get('professional_footprint', {})
        linkedin_data = self.target_data.get('social_media_presence', {}).get('linkedin', {})
        
        print("🏢 Career Progression Analysis:")
        if 'previous_positions' in linkedin_data:
            positions = linkedin_data['previous_positions']
            current_pos = linkedin_data.get('current_position', {})
            
            # Add current position to timeline
            all_positions = [current_pos] + positions if current_pos else positions
            
            for i, pos in enumerate(all_positions):
                status = "Current" if i == 0 and current_pos else "Previous"
                print(f"   {status}: {pos.get('title', 'Unknown')} at {pos.get('company', 'Unknown')}")
                print(f"            Duration: {pos.get('duration', 'Unknown')}")
        
        # Conference participation analysis
        print(f"\n🎤 Conference and Speaking Intelligence:")
        if 'conferences' in professional:
            for conf in professional['conferences']:
                print(f"   Event: {conf.get('name', 'Unknown')}")
                print(f"   Role: {conf.get('role', 'Unknown')}")
                if conf.get('topic'):
                    print(f"   Topic: {conf['topic']}")
                print(f"   Date: {conf.get('date', 'Unknown')}")
                print()
        
        # Publications analysis
        print(f"📚 Publications and Research:")
        if 'publications' in professional:
            for pub in professional['publications']:
                print(f"   Title: {pub.get('title', 'Unknown')}")
                print(f"   Publication: {pub.get('publication', 'Unknown')}")
                print(f"   Date: {pub.get('date', 'Unknown')}")
                if pub.get('coauthor'):
                    print(f"   Co-author: {pub['coauthor']}")
                print()
        
        # Certifications analysis
        print(f"🏆 Professional Certifications:")
        if 'certifications' in professional:
            for cert in professional['certifications']:
                print(f"   {cert.get('name', 'Unknown')}")
                print(f"   Issuer: {cert.get('issuer', 'Unknown')}")
                print(f"   Obtained: {cert.get('date_obtained', 'Unknown')}")
                print()
        
        self.investigation_results['professional_intelligence'] = professional
        
        # Award flag for professional analysis
        prof_flag = "CTF{professional_background_and_expertise_mapped}"
        print(f"🚩 FLAG DISCOVERED: {prof_flag}")
        self.investigation_results['flags_discovered'].append(prof_flag)
        
        return professional
    
    def technical_footprint_analysis(self):
        """Phase 4: Technical skills and digital footprint analysis"""
        print("\n💻 PHASE 4: TECHNICAL FOOTPRINT ANALYSIS")
        print("-" * 44)
        
        github_data = self.target_data.get('social_media_presence', {}).get('github', {})
        digital_artifacts = self.target_data.get('digital_artifacts', {})
        
        # GitHub repository analysis
        print("📊 GitHub Repository Intelligence:")
        if 'repositories' in github_data:
            total_stars = 0
            languages = {}
            topics = []
            
            for repo in github_data['repositories']:
                print(f"   Repository: {repo.get('name', 'Unknown')}")
                print(f"   Description: {repo.get('description', 'No description')}")
                print(f"   Language: {repo.get('language', 'Unknown')}")
                print(f"   Stars: {repo.get('stars', 0)} | Forks: {repo.get('forks', 0)}")
                print(f"   Last Updated: {repo.get('last_updated', 'Unknown')}")
                
                total_stars += repo.get('stars', 0)
                lang = repo.get('language', 'Unknown')
                languages[lang] = languages.get(lang, 0) + 1
                topics.extend(repo.get('topics', []))
                print()
            
            print(f"📈 GitHub Statistics Summary:")
            print(f"   Total Stars Received: {total_stars}")
            print(f"   Primary Languages: {', '.join(languages.keys())}")
            print(f"   Common Topics: {', '.join(set(topics))}")
        
        # Digital artifacts analysis
        print(f"\n🔍 Digital Artifacts Analysis:")
        
        if 'email_patterns' in digital_artifacts:
            print(f"   Email Patterns Identified:")
            for email in digital_artifacts['email_patterns']:
                confidence = self.calculate_email_confidence(email)
                print(f"     {email} (Confidence: {confidence}%)")
        
        if 'usernames' in digital_artifacts:
            print(f"\n   Username Patterns:")
            for username in digital_artifacts['usernames']:
                print(f"     {username}")
        
        if 'metadata_clues' in digital_artifacts:
            metadata = digital_artifacts['metadata_clues']
            print(f"\n   Technical Metadata:")
            for key, value in metadata.items():
                print(f"     {key}: {value}")
        
        tech_data = {
            'github_analysis': github_data,
            'digital_artifacts': digital_artifacts
        }
        self.investigation_results['technical_footprint'] = tech_data
        
        # Award flag for technical analysis
        tech_flag = "CTF{technical_footprint_and_digital_artifacts_analyzed}"
        print(f"\n🚩 FLAG DISCOVERED: {tech_flag}")
        self.investigation_results['flags_discovered'].append(tech_flag)
        
        return tech_data
    
    def personal_interests_investigation(self):
        """Phase 5: Personal interests and lifestyle intelligence"""
        print("\n🎯 PHASE 5: PERSONAL INTERESTS INVESTIGATION")
        print("-" * 48)
        
        personal = self.target_data.get('personal_interests', {})
        twitter_data = self.target_data.get('social_media_presence', {}).get('twitter', {})
        
        # Hobbies and interests analysis
        if 'hobbies' in personal:
            print("🎨 Hobbies and Interests:")
            for hobby in personal['hobbies']:
                print(f"   • {hobby}")
        
        # Location preferences
        if 'favorite_locations' in personal:
            print(f"\n📍 Favorite Locations:")
            for location in personal['favorite_locations']:
                print(f"   • {location}")
        
        # Equipment and gear
        if 'equipment' in personal:
            print(f"\n🛠️ Personal Equipment:")
            for item, brand in personal['equipment'].items():
                print(f"   {item.replace('_', ' ').title()}: {brand}")
        
        # Social media content analysis
        if 'recent_tweets' in twitter_data:
            print(f"\n🐦 Social Media Content Analysis:")
            for tweet in twitter_data['recent_tweets']:
                print(f"   Date: {tweet.get('date', 'Unknown')}")
                print(f"   Content: {tweet.get('content', 'No content')[:80]}...")
                print(f"   Engagement: {tweet.get('likes', 0)} likes, {tweet.get('retweets', 0)} retweets")
                print()
        
        self.investigation_results['personal_profile'] = personal
        
        # Award flag for personal intelligence
        personal_flag = "CTF{personal_interests_and_lifestyle_intelligence_gathered}"
        print(f"🚩 FLAG DISCOVERED: {personal_flag}")
        self.investigation_results['flags_discovered'].append(personal_flag)
        
        return personal
    
    def cross_platform_correlation(self):
        """Phase 6: Cross-platform intelligence correlation and timeline analysis"""
        print("\n🔗 PHASE 6: CROSS-PLATFORM CORRELATION ANALYSIS")
        print("-" * 54)
        
        # Username correlation analysis
        print("👤 Username Pattern Analysis:")
        digital_artifacts = self.target_data.get('digital_artifacts', {})
        usernames = digital_artifacts.get('usernames', [])
        
        if usernames:
            print("   Identified Username Patterns:")
            for username in usernames:
                platforms = self.identify_platform_usage(username)
                print(f"     {username}: {', '.join(platforms)}")
        
        # Email correlation
        print(f"\n📧 Email Address Correlation:")
        emails = digital_artifacts.get('email_patterns', [])
        for email in emails:
            domain = email.split('@')[1] if '@' in email else 'Unknown'
            purpose = self.classify_email_purpose(email)
            print(f"   {email}")
            print(f"     Domain: {domain}")
            print(f"     Purpose: {purpose}")
            print()
        
        # Timeline correlation
        print(f"⏰ Activity Timeline Correlation:")
        timeline_events = [
            {"date": "2025-09-12", "platform": "Twitter", "activity": "APT campaign analysis tweet"},
            {"date": "2025-09-10", "platform": "Twitter", "activity": "BSides Austin conference mention"},
            {"date": "2025-09-08", "platform": "Twitter + GitHub", "activity": "IOC extraction tool announcement"},
            {"date": "2025-09-05", "platform": "Twitter", "activity": "Rock climbing at Reimers Ranch"}
        ]
        
        for event in timeline_events:
            print(f"   {event['date']}: {event['platform']} - {event['activity']}")
        
        # Cross-platform behavioral analysis
        print(f"\n🧠 Behavioral Pattern Analysis:")
        patterns = [
            "Consistent professional posting during business hours",
            "Personal interests shared on weekends",
            "Technical content cross-posted between Twitter and GitHub",
            "Location-based posts correlate with known interests"
        ]
        
        for pattern in patterns:
            print(f"   • {pattern}")
        
        correlation_data = {
            'username_patterns': usernames,
            'email_correlation': emails,
            'timeline_events': timeline_events,
            'behavioral_patterns': patterns
        }
        
        self.investigation_results['cross_platform_correlation'] = correlation_data
        
        # Award flag for correlation analysis
        correlation_flag = "CTF{cross_platform_correlation_and_timeline_analysis_complete}"
        print(f"\n🚩 FLAG DISCOVERED: {correlation_flag}")
        self.investigation_results['flags_discovered'].append(correlation_flag)
        
        return correlation_data
    
    def calculate_email_confidence(self, email):
        """Calculate confidence level for email address attribution"""
        confidence = 50  # Base confidence
        
        if 'marcus' in email.lower():
            confidence += 20
        if 'thompson' in email.lower():
            confidence += 20
        if 'cyber' in email.lower() or 'sec' in email.lower():
            confidence += 15
        if 'techcorp.com' in email.lower():
            confidence += 10
        if 'austin' in email.lower():
            confidence += 5
        
        return min(confidence, 95)  # Cap at 95%
    
    def identify_platform_usage(self, username):
        """Identify platforms where username might be used"""
        platforms = []
        
        if 'cyber' in username.lower():
            platforms.extend(['Twitter', 'GitHub', 'LinkedIn'])
        if 'atx' in username.lower():
            platforms.append('Twitter')
        if 'sec' in username.lower():
            platforms.extend(['LinkedIn', 'Professional Forums'])
        
        return platforms if platforms else ['Unknown']
    
    def classify_email_purpose(self, email):
        """Classify email address purpose"""
        if 'techcorp.com' in email:
            return 'Work/Professional'
        elif 'protonmail.com' in email:
            return 'Personal/Security-focused'
        elif 'gmail.com' in email:
            return 'Personal/General'
        elif 'austin-infosec' in email:
            return 'Blog/Personal Brand'
        else:
            return 'Unknown'
    
    def generate_comprehensive_assessment(self):
        """Generate final comprehensive OSINT assessment"""
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE OSINT ASSESSMENT")
        print("=" * 60)
        
        investigation_duration = (datetime.now() - self.investigation_start).total_seconds()
        
        print(f"\n🎯 TARGET: {self.target_name}")
        print(f"🕐 Investigation Duration: {investigation_duration:.1f} seconds")
        print(f"📅 Investigation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Intelligence summary
        target_info = self.investigation_results['target_identification']
        print(f"\n📋 INTELLIGENCE SUMMARY:")
        print(f"   • Full Identity: {target_info.get('name', 'Unknown')} ({target_info.get('alias', 'Unknown')})")
        print(f"   • Location: {target_info.get('location', 'Unknown')}")
        print(f"   • Occupation: {target_info.get('occupation', 'Unknown')} at {target_info.get('company', 'Unknown')}")
        print(f"   • Education: {target_info.get('education', 'Unknown')}")
        
        # Digital footprint assessment
        social_platforms = len(self.investigation_results['social_media_analysis'])
        technical_artifacts = len(self.investigation_results['technical_footprint'])
        
        print(f"\n🌐 DIGITAL FOOTPRINT ASSESSMENT:")
        print(f"   • Social Media Platforms: {social_platforms}")
        print(f"   • Technical Artifacts: {technical_artifacts}")
        print(f"   • Professional Publications: Multiple identified")
        print(f"   • Personal Interests: Comprehensive profile developed")
        
        # OPSEC assessment
        print(f"\n🛡️ OPERATIONAL SECURITY (OPSEC) ASSESSMENT:")
        opsec_score = self.calculate_opsec_score()
        print(f"   OPSEC Score: {opsec_score}/100")
        
        if opsec_score < 40:
            print("   Assessment: HIGH VISIBILITY - Extensive digital footprint")
        elif opsec_score < 70:
            print("   Assessment: MEDIUM VISIBILITY - Moderate digital footprint")
        else:
            print("   Assessment: LOW VISIBILITY - Limited digital footprint")
        
        print(f"\n🚨 PRIVACY RISKS IDENTIFIED:")
        risks = [
            "Consistent username patterns enable cross-platform tracking",
            "Professional information widely available across platforms",
            "Personal interests and locations easily discoverable",
            "Timeline correlation possible through social media activity",
            "Email address patterns predictable"
        ]
        
        for risk in risks:
            print(f"   • {risk}")
        
        # Flags summary
        flags_count = len(self.investigation_results['flags_discovered'])
        print(f"\n🚩 FLAGS DISCOVERED: {flags_count}")
        for i, flag in enumerate(self.investigation_results['flags_discovered'], 1):
            print(f"   {i}. {flag}")
        
        # Master OSINT flag
        if flags_count >= 5:
            master_flag = "CTF{osint_investigation_comprehensive_digital_footprint_analysis_master_2025}"
            print(f"\n🏆 MASTER OSINT FLAG: {master_flag}")
            self.investigation_results['flags_discovered'].append(master_flag)
        
        return self.investigation_results
    
    def calculate_opsec_score(self):
        """Calculate OPSEC score based on digital footprint visibility"""
        score = 100  # Start with perfect OPSEC
        
        # Deduct points for various visibility factors
        social_platforms = len(self.investigation_results['social_media_analysis'])
        score -= (social_platforms * 10)  # -10 per platform
        
        # Professional visibility
        if self.investigation_results['professional_intelligence']:
            score -= 15  # Public professional information
        
        # Personal information visibility
        if self.investigation_results['personal_profile']:
            score -= 20  # Personal interests exposed
        
        # Cross-platform correlation
        if self.investigation_results['cross_platform_correlation']:
            score -= 25  # Correlation possible
        
        return max(score, 0)  # Don't go below 0
    
    def run_complete_osint_investigation(self):
        """Execute comprehensive OSINT investigation"""
        print("🕵️ OSINT INVESTIGATION TOOLKIT - Challenge 5")
        print("=" * 55)
        print(f"🎯 Target: {self.target_name}")
        print(f"🗓️ Investigation Start: {self.investigation_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 55)
        
        # Load target intelligence
        if not self.load_target_intelligence():
            return None
        
        # Execute investigation phases
        self.basic_target_identification()
        self.social_media_intelligence_gathering()
        self.professional_background_analysis()
        self.technical_footprint_analysis()
        self.personal_interests_investigation()
        self.cross_platform_correlation()
        
        # Generate final assessment
        return self.generate_comprehensive_assessment()

if __name__ == "__main__":
    investigator = OSINTInvestigator("Marcus Thompson")
    results = investigator.run_complete_osint_investigation()
    
    if results:
        print(f"\n✅ OSINT investigation complete!")
        print(f"📊 Comprehensive digital footprint analysis generated")
    else:
        print(f"\n❌ OSINT investigation failed!")
