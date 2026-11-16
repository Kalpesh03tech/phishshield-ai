"""
PhishShield AI 2.0 - Application Launcher
Forwards to FastAPI/Uvicorn server (main:app).
"""

if __name__ == '__main__':
    import uvicorn
    from config import settings

    print("\n=======================================================")
    print("   PhishShield AI 2.0 - Real-Time Threat Intelligence Platform")
    print(f"   Dashboard: http://127.0.0.1:{settings.SERVER_PORT}")
    print("=======================================================\n")

    uvicorn.run(
        "main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.DEBUG_MODE,
        log_level="info"
    )
