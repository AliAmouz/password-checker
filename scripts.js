document.addEventListener("DOMContentLoaded", function () {
  const passwordInput = document.getElementById("password");
  const resultDiv = document.getElementById("result");

  passwordInput.addEventListener("input", function () {
    const password = passwordInput.value;
    fetch("check_password.php", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "password=" + encodeURIComponent(password),
    })
      .then((response) => response.json())
      .then((data) => {
        let strengthText;
        switch (data.strength) {
          case 1:
          case 2:
            strengthText = "Weak";
            resultDiv.style.color = "red";
            break;
          case 3:
            strengthText = "Moderate";
            resultDiv.style.color = "orange";
            break;
          case 4:
          case 5:
            strengthText = "Strong";
            resultDiv.style.color = "green";
            break;
          default:
            strengthText = "";
        }
        resultDiv.textContent = "Password Strength: " + strengthText;
      });
  });
});
