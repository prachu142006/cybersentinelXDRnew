import requests

def get_location(ip_address):

    # Localhost ke liye demo location
    if ip_address in ["127.0.0.1", "localhost"]:
        return {
            "country": "India",
            "city": "Pune",
            "latitude": 18.5204,
            "longitude": 73.8567
        }

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip_address}"
        )

        data = response.json()

        if data["status"] == "success":

            return {

                "country": data["country"],
                "city": data["city"],
                "latitude": data["lat"],
                "longitude": data["lon"]

            }

    except:

        pass

    return {

        "country": "Unknown",
        "city": "Unknown",
        "latitude": 0,
        "longitude": 0

    }