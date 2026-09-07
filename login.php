<?php

session_start();

require_once "db.php";

$message = "";
$message_type = "";


/* ==========================================
   LOGIN PROCESS
========================================== */

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    /* Get form values */

    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";

    /* ==========================================
       CHECK EMPTY FIELDS
    ========================================== */

    if ($email === "" || $password === "") {

        $message = "Please enter email and password.";
        $message_type = "error";

    }


    /* ==========================================
       CHECK EMAIL FORMAT
    ========================================== */

    elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $message = "Please enter a valid email address.";
        $message_type = "error";

    }


    else {

        /* ==========================================
           FIND USER USING EMAIL
        ========================================== */

        $sql = "
            SELECT id, full_name, email, password
            FROM users
            WHERE email = ?
            LIMIT 1
        ";


        $stmt = mysqli_prepare($conn, $sql);


        if (!$stmt) {

            $message = "Something went wrong. Please try again.";
            $message_type = "error";

        }

        else {

            /* Bind email */

            mysqli_stmt_bind_param(
                $stmt,
                "s",
                $email
            );


            /* Execute query */

            mysqli_stmt_execute($stmt);


            /* Get result */

            $result = mysqli_stmt_get_result($stmt);


            /* ==========================================
               CHECK EMAIL EXISTS
            ========================================== */

            if (mysqli_num_rows($result) === 1) {

                $user = mysqli_fetch_assoc($result);


                /* ==========================================
                   VERIFY PASSWORD
                ========================================== */

                if (
                    password_verify(
                        $password,
                        $user["password"]
                    )
                ) {

                    /* ==========================================
                       LOGIN SUCCESS
                    ========================================== */

                    /*
                     * Regenerate session ID
                     * after successful login
                     */

                    session_regenerate_id(true);


                    /* Store user information */

                    $_SESSION["user_id"] =
                        $user["id"];

                    $_SESSION["user_name"] =
                        $user["full_name"];

                    $_SESSION["user_email"] =
                        $user["email"];


                    /* ==========================================
                       ONLY SUCCESSFUL LOGIN
                       GO TO DASHBOARD
                    ========================================== */

                    header("Location: dashboard.php");

                    exit();

                }

                else {

                    /* Wrong password */

                    $message =
                        "Incorrect email or password.";

                    $message_type = "error";

                }

            }

            else {

                /* Email does not exist */

                $message =
                    "Incorrect email or password.";

                $message_type = "error";

            }


            mysqli_stmt_close($stmt);

        }

    }

}

?>


<!DOCTYPE html>

<html lang="en">


<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>Login - Care & Carry Hub</title>

    <link rel="stylesheet"
          href="style.css">

</head>


<body>


<!-- ================= NAVBAR ================= -->

<nav class="navbar">

    <div class="logo">

        Care <span>&</span> Carry

    </div>


    <ul class="nav-links">

        <li>

            <a href="index.php">
                Home
            </a>

        </li>


        <li>

            <a href="register.php">
                Register
            </a>

        </li>

    </ul>

</nav>



<!-- ================= LOGIN SECTION ================= -->

<div class="auth-container">


    <div class="auth-box">


        <h2>
            Welcome Back
        </h2>


        <p class="auth-subtitle">

            Login to your Care & Carry account

        </p>



        <!-- ================= ERROR MESSAGE ================= -->

        <?php if (!empty($message)): ?>

            <div class="error-message">

                <?php

                echo htmlspecialchars($message);

                ?>

            </div>

        <?php endif; ?>



        <!-- ================= LOGIN FORM ================= -->

        <form
            method="POST"
            action="login.php"
        >


            <!-- EMAIL -->

            <div class="form-group">

                <label for="email">
                    Email Address
                </label>


                <input
                    type="email"
                    id="email"
                    name="email"
                    placeholder="Enter your email"
                    value="<?php echo htmlspecialchars($email ?? ''); ?>"
                    required
                >

            </div>



            <!-- PASSWORD -->

            <div class="form-group">

                <label for="password">
                    Password
                </label>


                <input
                    type="password"
                    id="password"
                    name="password"
                    placeholder="Enter your password"
                    required
                >

            </div>



            <!-- LOGIN BUTTON -->

            <button
                type="submit"
                class="btn full-btn">

                Login

            </button>


        </form>



        <!-- ================= REGISTER LINK ================= -->

        <p class="auth-link">

            Don't have an account?

            <a href="register.php">
                Create Account
            </a>

        </p>


    </div>

</div>



<!-- ================= FOOTER ================= -->

<footer class="footer">

    <p>

        © 2026 Care & Carry Hub.
        All Rights Reserved.

    </p>

</footer>


</body>

</html>