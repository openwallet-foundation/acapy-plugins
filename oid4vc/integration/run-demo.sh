#!/bin/bash
set -e

# Default configuration
USE_DOCKER_EMULATOR=false
APPIUM_URL="http://localhost:4723"

# Help message
function show_help {
    echo "Usage: ./run-demo.sh [OPTIONS]"
    echo "Runs the OID4VC Android Demo."
    echo ""
    echo "Options:"
    echo "  --docker-emulator    Run Android Emulator & Appium inside Docker (Requires KVM)"
    echo "  --local-emulator     Use local Android Emulator & Appium (Default)"
    echo "  --appium-url URL     URL of the Appium server (Default: http://localhost:4723)"
    echo "  --help               Show this help message"
}

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --docker-emulator) USE_DOCKER_EMULATOR=true ;;
        --local-emulator) USE_DOCKER_EMULATOR=false ;;
        --appium-url) APPIUM_URL="$2"; shift ;;
        --help) show_help; exit 0 ;;
        *) echo "Unknown parameter passed: $1"; show_help; exit 1 ;;
    esac
    shift
done

echo "🚀 Starting OID4VC Android Demo..."

if [ "$USE_DOCKER_EMULATOR" = true ]; then
    echo "📱 Mode: Docker Emulator (Requires KVM)"
    echo "   - Android Device: Docker Container"
    echo "   - Appium: Docker Container"
    echo "   - ACA-Py: Docker Container"
    
    # Start everything including emulator profile
    docker compose -f docker-compose.demo.yml --profile emulator up -d
    
    echo "⏳ Waiting for Emulator to boot..."
    # In a real script, we'd wait for healthchecks
    sleep 10
    
    echo "✅ Environment running!"
    echo "   - VNC Viewer: http://localhost:6080"
    echo "   - Appium: http://localhost:4723"
    
    # Run tests inside docker network
    # Note: Inside docker, appium is at http://appium:4723
    docker compose -f docker-compose.demo.yml --profile runner run \
        -e APPIUM_URL="http://appium:4723" \
        demo-runner
else
    echo "📱 Mode: Local Emulator"
    echo "   - Android Device: Local (Host)"
    echo "   - Appium: Local (Host)"
    echo "   - ACA-Py: Docker Container"
    
    echo "⚠️  Ensure you have an Android Emulator running and Appium listening at $APPIUM_URL"
    
    # Check if app.apk needs to be built
    if [ ! -f "app.apk" ]; then
        echo "🏗️  app.apk not found. Building SpruceID Showcase wallet..."
        docker compose -f docker-compose.demo.yml --profile builder run --rm wallet-builder
    fi
    
    # Check if a compatible wallet is already installed on the emulator
    echo "🔍 Checking for installed wallet apps..."
    
    WALLET_FOUND=false
    WALLET_PACKAGE=""
    
    # Check for various wallet apps
    if adb shell pm list packages | grep -q "ca.bc.gov.BCWallet"; then
        WALLET_FOUND=true
        WALLET_PACKAGE="ca.bc.gov.BCWallet"
        echo "✅ BC Wallet is installed"
    elif adb shell pm list packages | grep -q "com.spruceid.mobilesdkexample"; then
        WALLET_FOUND=true
        WALLET_PACKAGE="com.spruceid.mobilesdkexample"
        echo "✅ SpruceID Showcase is installed"
    elif adb shell pm list packages | grep -q "io.lissi.mobile.android"; then
        WALLET_FOUND=true
        WALLET_PACKAGE="io.lissi.mobile.android"
        echo "✅ Lissi Wallet is installed"
    fi
    
    if [ "$WALLET_FOUND" = false ]; then
        echo "⚠️  No compatible wallet found on emulator."
        echo ""
        echo "📋 Installation Options:"
        echo ""
        echo "1. Install BC Wallet from Play Store:"
        echo "   https://play.google.com/store/apps/details?id=ca.bc.gov.BCWallet"
        echo ""
        echo "2. Install Lissi Wallet from Play Store:"
        echo "   https://play.google.com/store/apps/details?id=io.lissi.mobile.android"
        echo ""
        echo "3. Build SpruceID Showcase from source:"
        echo "   git clone https://github.com/spruceid/sprucekit-mobile"
        echo "   cd sprucekit-mobile/android && ./gradlew :Showcase:assembleDebug"
        echo "   adb install Showcase/build/outputs/apk/debug/Showcase-debug.apk"
        echo ""
        echo "4. Place your own wallet APK here as 'app.apk' and re-run"
        echo ""
        
        # Check for local APK
        if [ -f "app.apk" ]; then
            echo "📦 Found local app.apk, installing..."
            adb install -r app.apk
            echo "✅ APK installed. Re-run this script to continue."
        fi
    else
        export ANDROID_APP_PACKAGE="$WALLET_PACKAGE"
        echo "✅ Will test with: $WALLET_PACKAGE"
    fi

    # Start only ACA-Py services
    docker compose -f docker-compose.demo.yml up -d
    
    echo "✅ ACA-Py Environment running!"
    
    # Run tests using the runner, pointing to host appium
    # We use host.docker.internal to reach the host machine from the container
    if [[ "$APPIUM_URL" == *"localhost"* ]]; then
        DOCKER_APPIUM_URL=${APPIUM_URL/localhost/host.docker.internal}
    else
        DOCKER_APPIUM_URL=$APPIUM_URL
    fi
    
    echo "🏃 Running tests against $DOCKER_APPIUM_URL..."
    docker compose -f docker-compose.demo.yml --profile runner run \
        -e APPIUM_URL="$DOCKER_APPIUM_URL" \
        demo-runner
fi

echo "🎉 Demo Complete!"
